#pragma once

#include <asn1/ast.hpp>
#include <asn1/lexer.hpp>
#include <cstdint>
#include <string_view>

namespace asn1 {

struct Parser {
    FixedVector<Token, 1024> tokens{};
    std::size_t pos = 0;
    AstModule module{};

    constexpr auto peek() const -> const Token& {
        return tokens[pos];
    }

    constexpr auto advance() -> const Token& {
        return tokens[pos++];
    }

    constexpr bool check(TokenKind k) const {
        return peek().kind == k;
    }

    constexpr auto expect(TokenKind k) -> const Token& {
        auto& tok = tokens[pos];
        if (tok.kind != k) {
            // In consteval context this will produce a compile error
            // by accessing out of bounds
            struct ParseError {};
            throw ParseError{};
        }
        ++pos;
        return tok;
    }

    constexpr bool try_consume(TokenKind k) {
        if (check(k)) { ++pos; return true; }
        return false;
    }

    constexpr auto parse() -> AstModule {
        parse_module_header();
        parse_module_body();
        expect(TokenKind::KwEnd);
        return module;
    }

    constexpr void parse_module_header() {
        // ModuleName DEFINITIONS [tag-default] ::= BEGIN
        module.name = advance().text; // module name (identifier)
        expect(TokenKind::KwDefinitions);

        // Optional tag default
        if (check(TokenKind::KwExplicit)) {
            advance();
            expect(TokenKind::KwTags);
            module.default_tag_mode = TagMode::Explicit;
        } else if (check(TokenKind::KwImplicit)) {
            advance();
            expect(TokenKind::KwTags);
            module.default_tag_mode = TagMode::Implicit;
        } else if (check(TokenKind::KwAutomatic)) {
            advance();
            expect(TokenKind::KwTags);
            module.default_tag_mode = TagMode::Automatic;
        }

        expect(TokenKind::Assignment);
        expect(TokenKind::KwBegin);
    }

    constexpr void parse_module_body() {
        // Optional IMPORTS
        if (check(TokenKind::KwImports)) {
            parse_imports();
        }

        // Assignments until END
        while (!check(TokenKind::KwEnd) && !check(TokenKind::Eof)) {
            parse_assignment();
        }
    }

    constexpr void parse_imports() {
        expect(TokenKind::KwImports);
        // Skip everything until semicolon
        while (!check(TokenKind::Semicolon) && !check(TokenKind::Eof)) {
            advance();
        }
        expect(TokenKind::Semicolon);
    }

    constexpr void parse_assignment() {
        auto& name_tok = advance(); // type or value name

        // Value assignment: name Type ::= Value
        // Type assignment: Name ::= Type
        // Distinguish: type names start uppercase, value names start lowercase
        // But also: OID value assignments like  name OBJECT IDENTIFIER ::= { ... }

        if (check(TokenKind::KwObjectIdentifier)) {
            // OID value assignment
            advance(); // consume OBJECT IDENTIFIER
            expect(TokenKind::Assignment);
            auto va = parse_oid_value(name_tok.text);
            module.values.push_back(va);
            return;
        }

        if (check(TokenKind::Assignment)) {
            // Type assignment: Name ::= Type
            advance();
            auto node_idx = parse_type();
            TypeAssignment ta;
            ta.name = name_tok.text;
            ta.node_index = node_idx;
            module.types.push_back(ta);
            return;
        }

        // Could be: name Type ::= value  (value assignment with non-OID type)
        // For our purposes, skip value assignments we don't understand
        // by consuming until the next top-level assignment or END
        skip_to_next_assignment();
    }

    constexpr void skip_to_next_assignment() {
        // Skip until we see Identifier ::= or keyword at top level
        int depth = 0;
        while (!check(TokenKind::Eof) && !check(TokenKind::KwEnd)) {
            if (check(TokenKind::LBrace)) { ++depth; advance(); continue; }
            if (check(TokenKind::RBrace)) { --depth; advance(); continue; }
            if (depth == 0 && check(TokenKind::Assignment)) {
                // Backtrack: the identifier before ::= is the next assignment name
                // We already consumed it, so just consume ::= and parse
                // Actually we need to be more careful. Let's just look ahead.
                advance(); // consume ::=
                // Now we're at the type of the next assignment - but we've lost the name.
                // Better approach: look for pattern Identifier ::= at depth 0
                break;
            }
            advance();
        }
    }

    constexpr auto parse_oid_value(FixedString<64> name) -> ValueAssignment {
        ValueAssignment va;
        va.name = name;
        va.type_name = "OBJECT IDENTIFIER";
        expect(TokenKind::LBrace);
        while (!check(TokenKind::RBrace) && !check(TokenKind::Eof)) {
            if (check(TokenKind::Number)) {
                // Bare number
                auto& tok = advance();
                va.oid_components.push_back(parse_number(tok.text.view()));
                FixedString<64> empty{};
                va.oid_names.push_back(empty);
            } else if (check(TokenKind::Identifier)) {
                auto& tok = advance();
                if (check(TokenKind::LParen)) {
                    // name(number)
                    advance(); // (
                    auto& num_tok = expect(TokenKind::Number);
                    va.oid_components.push_back(parse_number(num_tok.text.view()));
                    va.oid_names.push_back(tok.text);
                    expect(TokenKind::RParen);
                } else {
                    // Just a reference name
                    va.oid_components.push_back(0);
                    va.oid_names.push_back(tok.text);
                }
            } else {
                advance(); // skip unexpected
            }
        }
        expect(TokenKind::RBrace);
        return va;
    }

    constexpr auto parse_type() -> std::size_t {
        // Tagged type: [class number] EXPLICIT/IMPLICIT Type
        if (check(TokenKind::LBracket)) {
            return parse_tagged_type();
        }

        // SEQUENCE
        if (check(TokenKind::KwSequence)) {
            advance();
            if (check(TokenKind::LBrace)) {
                return parse_sequence_body();
            }
            // SEQUENCE SIZE (...) OF Type  or  SEQUENCE OF Type
            skip_size_constraint();
            if (try_consume(TokenKind::KwOf)) {
                AstNode node;
                node.kind = AstNodeKind::SequenceOf;
                node.inner_index = parse_type();
                return module.add_node(node);
            }
            // Bare SEQUENCE (unlikely but handle as empty sequence)
            AstNode node;
            node.kind = AstNodeKind::Sequence;
            return module.add_node(node);
        }

        // SET OF
        if (check(TokenKind::KwSet)) {
            advance();
            skip_size_constraint();
            if (try_consume(TokenKind::KwOf)) {
                AstNode node;
                node.kind = AstNodeKind::SetOf;
                node.inner_index = parse_type();
                return module.add_node(node);
            }
            // SET { ... } - not needed for our use case, treat as sequence
            if (check(TokenKind::LBrace)) {
                return parse_sequence_body();
            }
            AstNode node;
            node.kind = AstNodeKind::Sequence;
            return module.add_node(node);
        }

        // CHOICE
        if (check(TokenKind::KwChoice)) {
            advance();
            return parse_choice_body();
        }

        // INTEGER
        if (check(TokenKind::KwInteger)) {
            advance();
            AstNode node;
            node.kind = AstNodeKind::Integer;
            // Optional named numbers: INTEGER { name(val), ... }
            if (check(TokenKind::LBrace)) {
                advance();
                parse_named_numbers(node);
                expect(TokenKind::RBrace);
            }
            // Skip inline constraints like (0..MAX)
            skip_constraint();
            return module.add_node(node);
        }

        // ENUMERATED
        if (check(TokenKind::KwEnumerated)) {
            advance();
            AstNode node;
            node.kind = AstNodeKind::Enumerated;
            if (check(TokenKind::LBrace)) {
                advance();
                parse_named_numbers(node);
                expect(TokenKind::RBrace);
            }
            return module.add_node(node);
        }

        // BIT STRING
        if (check(TokenKind::KwBitString)) {
            advance();
            AstNode node;
            node.kind = AstNodeKind::BitString;
            // Optional named bits
            if (check(TokenKind::LBrace)) {
                advance();
                parse_named_numbers(node);
                expect(TokenKind::RBrace);
            }
            skip_constraint();
            return module.add_node(node);
        }

        // OCTET STRING
        if (check(TokenKind::KwOctetString)) {
            advance();
            AstNode node;
            node.kind = AstNodeKind::OctetString;
            skip_constraint();
            return module.add_node(node);
        }

        // OBJECT IDENTIFIER
        if (check(TokenKind::KwObjectIdentifier)) {
            advance();
            AstNode node;
            node.kind = AstNodeKind::ObjectIdentifier;
            return module.add_node(node);
        }

        // BOOLEAN
        if (check(TokenKind::KwBoolean)) {
            advance();
            AstNode node;
            node.kind = AstNodeKind::Boolean;
            return module.add_node(node);
        }

        // NULL
        if (check(TokenKind::KwNull)) {
            advance();
            AstNode node;
            node.kind = AstNodeKind::Null;
            return module.add_node(node);
        }

        // String types — all produce simple leaf nodes
        if (check(TokenKind::KwUtf8String))      { advance(); AstNode node; node.kind = AstNodeKind::Utf8String;      skip_constraint(); return module.add_node(node); }
        if (check(TokenKind::KwPrintableString)) { advance(); AstNode node; node.kind = AstNodeKind::PrintableString; skip_constraint(); return module.add_node(node); }
        if (check(TokenKind::KwIA5String))       { advance(); AstNode node; node.kind = AstNodeKind::IA5String;       skip_constraint(); return module.add_node(node); }
        if (check(TokenKind::KwVisibleString))   { advance(); AstNode node; node.kind = AstNodeKind::VisibleString;   skip_constraint(); return module.add_node(node); }
        if (check(TokenKind::KwBMPString))       { advance(); AstNode node; node.kind = AstNodeKind::BMPString;       skip_constraint(); return module.add_node(node); }
        if (check(TokenKind::KwTeletexString))   { advance(); AstNode node; node.kind = AstNodeKind::TeletexString;   skip_constraint(); return module.add_node(node); }
        if (check(TokenKind::KwNumericString))   { advance(); AstNode node; node.kind = AstNodeKind::NumericString;   skip_constraint(); return module.add_node(node); }
        if (check(TokenKind::KwUniversalString)) { advance(); AstNode node; node.kind = AstNodeKind::UniversalString; skip_constraint(); return module.add_node(node); }
        if (check(TokenKind::KwGeneralString))   { advance(); AstNode node; node.kind = AstNodeKind::GeneralString;   skip_constraint(); return module.add_node(node); }

        // Time types
        if (check(TokenKind::KwUtcTime))         { advance(); AstNode node; node.kind = AstNodeKind::UtcTime;         return module.add_node(node); }
        if (check(TokenKind::KwGeneralizedTime)) { advance(); AstNode node; node.kind = AstNodeKind::GeneralizedTime; return module.add_node(node); }

        // ANY DEFINED BY identifier
        if (check(TokenKind::KwAny)) {
            advance();
            AstNode node;
            node.kind = AstNodeKind::AnyDefinedBy;
            if (try_consume(TokenKind::KwDefined)) {
                expect(TokenKind::KwBy);
                node.defined_by = advance().text;
            }
            return module.add_node(node);
        }

        // Type reference (identifier)
        if (check(TokenKind::Identifier)) {
            auto& tok = advance();
            AstNode node;
            node.kind = AstNodeKind::TypeRef;
            node.name = tok.text;
            return module.add_node(node);
        }

        // Fallback: shouldn't reach here in valid ASN.1
        struct UnexpectedToken {};
        throw UnexpectedToken{};
    }

    constexpr auto parse_tagged_type() -> std::size_t {
        expect(TokenKind::LBracket);

        AstNode node;
        node.kind = AstNodeKind::Tagged;
        node.tag_class = TagClass::ContextSpecific;

        // Optional class
        if (check(TokenKind::KwUniversal)) {
            node.tag_class = TagClass::Universal;
            advance();
        } else if (check(TokenKind::KwApplication)) {
            node.tag_class = TagClass::Application;
            advance();
        } else if (check(TokenKind::KwPrivate)) {
            node.tag_class = TagClass::Private;
            advance();
        }

        auto& num_tok = expect(TokenKind::Number);
        node.tag_number = static_cast<uint32_t>(parse_number(num_tok.text.view()));

        expect(TokenKind::RBracket);

        // Optional EXPLICIT / IMPLICIT
        if (check(TokenKind::KwExplicit)) {
            node.tag_mode = TagMode::Explicit;
            advance();
        } else if (check(TokenKind::KwImplicit)) {
            node.tag_mode = TagMode::Implicit;
            advance();
        } else {
            // Use module default
            node.tag_mode = module.default_tag_mode;
        }

        node.inner_index = parse_type();
        return module.add_node(node);
    }

    constexpr auto parse_sequence_body() -> std::size_t {
        expect(TokenKind::LBrace);

        AstNode node;
        node.kind = AstNodeKind::Sequence;

        while (!check(TokenKind::RBrace) && !check(TokenKind::Eof)) {
            // Skip extensibility marker ...
            if (check(TokenKind::DotDot)) {
                advance();
                // May be followed by comma
                try_consume(TokenKind::Comma);
                continue;
            }

            auto field = parse_component();
            node.fields.push_back(field);

            // Comma between fields (optional before })
            try_consume(TokenKind::Comma);
        }

        expect(TokenKind::RBrace);
        return module.add_node(node);
    }

    constexpr auto parse_choice_body() -> std::size_t {
        expect(TokenKind::LBrace);

        AstNode node;
        node.kind = AstNodeKind::Choice;

        while (!check(TokenKind::RBrace) && !check(TokenKind::Eof)) {
            if (check(TokenKind::DotDot)) {
                advance();
                try_consume(TokenKind::Comma);
                continue;
            }

            auto field = parse_component();
            node.fields.push_back(field);
            try_consume(TokenKind::Comma);
        }

        expect(TokenKind::RBrace);
        return module.add_node(node);
    }

    constexpr auto parse_component() -> AstField {
        AstField field;
        field.name = advance().text; // field name
        field.type_index = parse_type();

        if (try_consume(TokenKind::KwOptional)) {
            field.optional = true;
        } else if (try_consume(TokenKind::KwDefault)) {
            field.has_default = true;
            // Parse default value - for our purposes, consume a simple value
            parse_default_value(field);
        }

        return field;
    }

    constexpr void parse_default_value(AstField& field) {
        // Default values can be: number, TRUE, FALSE, identifier, { ... }
        if (check(TokenKind::Number)) {
            field.default_int = parse_number(advance().text.view());
        } else if (check(TokenKind::KwTrue)) {
            field.default_int = 1;
            advance();
        } else if (check(TokenKind::KwFalse)) {
            field.default_int = 0;
            advance();
        } else if (check(TokenKind::Identifier)) {
            // Named value reference - store name in default_int as 0
            advance();
        } else if (check(TokenKind::LBrace)) {
            // Structured default - skip balanced braces
            skip_braces();
        }
    }

    constexpr void parse_named_numbers(AstNode& node) {
        while (!check(TokenKind::RBrace) && !check(TokenKind::Eof)) {
            if (check(TokenKind::DotDot)) {
                advance();
                try_consume(TokenKind::Comma);
                continue;
            }

            NamedNumber nn;
            nn.name = advance().text;
            expect(TokenKind::LParen);
            if (check(TokenKind::Number)) {
                nn.value = parse_number(advance().text.view());
            }
            expect(TokenKind::RParen);
            node.named_numbers.push_back(nn);

            try_consume(TokenKind::Comma);
        }
    }

    constexpr void skip_constraint() {
        if (check(TokenKind::LParen)) {
            skip_parens();
        }
    }

    constexpr void skip_size_constraint() {
        if (check(TokenKind::LParen)) {
            skip_parens();
        } else if (check(TokenKind::KwSize)) {
            advance();
            if (check(TokenKind::LParen)) {
                skip_parens();
            }
        }
    }

    constexpr void skip_parens() {
        int depth = 0;
        do {
            if (check(TokenKind::LParen)) ++depth;
            else if (check(TokenKind::RParen)) --depth;
            advance();
        } while (depth > 0 && !check(TokenKind::Eof));
    }

    constexpr void skip_braces() {
        int depth = 0;
        do {
            if (check(TokenKind::LBrace)) ++depth;
            else if (check(TokenKind::RBrace)) --depth;
            advance();
        } while (depth > 0 && !check(TokenKind::Eof));
    }

    static constexpr auto parse_number(std::string_view sv) -> int64_t {
        int64_t result = 0;
        for (char c : sv) {
            result = result * 10 + (c - '0');
        }
        return result;
    }
};

constexpr auto parse_module(std::string_view source) -> AstModule {
    Parser p;
    p.tokens = lex(source);
    return p.parse();
}

} // namespace asn1
