#pragma once

#include <asn1/fixed_string.hpp>
#include <asn1/fixed_vector.hpp>
#include <cstdint>
#include <string_view>

namespace asn1 {

enum class TokenKind : uint8_t {
    Identifier,
    Number,
    String,
    Assignment,     // ::=
    LBrace,         // {
    RBrace,         // }
    LBracket,       // [
    RBracket,       // ]
    LParen,         // (
    RParen,         // )
    Comma,
    Semicolon,
    Dot,
    DotDot,         // ..
    Pipe,           // |

    // Keywords
    KwSequence,
    KwSet,
    KwChoice,
    KwOf,
    KwInteger,
    KwBoolean,
    KwBitString,
    KwOctetString,
    KwObjectIdentifier,
    KwNull,
    KwOptional,
    KwDefault,
    KwExplicit,
    KwImplicit,
    KwAutomatic,
    KwDefinitions,
    KwBegin,
    KwEnd,
    KwImports,
    KwFrom,
    KwTags,
    KwAny,
    KwDefined,
    KwBy,
    KwSize,
    KwTrue,
    KwFalse,
    KwEnumerated,
    KwApplication,
    KwPrivate,
    KwUniversal,

    // String types
    KwUtf8String,
    KwPrintableString,
    KwIA5String,
    KwVisibleString,
    KwBMPString,
    KwTeletexString,
    KwNumericString,
    KwUniversalString,
    KwGeneralString,

    // Time types
    KwUtcTime,
    KwGeneralizedTime,

    Eof,
};

struct Token {
    TokenKind kind{};
    FixedString<64> text{};

    constexpr bool operator==(const Token&) const = default;
};

namespace detail {

struct KeywordEntry {
    std::string_view text;
    TokenKind kind;
};

inline constexpr KeywordEntry keywords[] = {
    {"SEQUENCE",          TokenKind::KwSequence},
    {"SET",               TokenKind::KwSet},
    {"CHOICE",            TokenKind::KwChoice},
    {"OF",                TokenKind::KwOf},
    {"INTEGER",           TokenKind::KwInteger},
    {"BOOLEAN",           TokenKind::KwBoolean},
    {"BIT",               TokenKind::KwBitString},    // "BIT STRING" handled specially
    {"OCTET",             TokenKind::KwOctetString},   // "OCTET STRING" handled specially
    {"OBJECT",            TokenKind::KwObjectIdentifier}, // "OBJECT IDENTIFIER" handled specially
    {"NULL",              TokenKind::KwNull},
    {"OPTIONAL",          TokenKind::KwOptional},
    {"DEFAULT",           TokenKind::KwDefault},
    {"EXPLICIT",          TokenKind::KwExplicit},
    {"IMPLICIT",          TokenKind::KwImplicit},
    {"AUTOMATIC",         TokenKind::KwAutomatic},
    {"DEFINITIONS",       TokenKind::KwDefinitions},
    {"BEGIN",             TokenKind::KwBegin},
    {"END",               TokenKind::KwEnd},
    {"IMPORTS",           TokenKind::KwImports},
    {"FROM",              TokenKind::KwFrom},
    {"TAGS",              TokenKind::KwTags},
    {"ANY",               TokenKind::KwAny},
    {"DEFINED",           TokenKind::KwDefined},
    {"BY",                TokenKind::KwBy},
    {"SIZE",              TokenKind::KwSize},
    {"TRUE",              TokenKind::KwTrue},
    {"FALSE",             TokenKind::KwFalse},
    {"ENUMERATED",        TokenKind::KwEnumerated},
    {"APPLICATION",       TokenKind::KwApplication},
    {"PRIVATE",           TokenKind::KwPrivate},
    {"UNIVERSAL",         TokenKind::KwUniversal},
    {"UTF8String",        TokenKind::KwUtf8String},
    {"PrintableString",   TokenKind::KwPrintableString},
    {"IA5String",         TokenKind::KwIA5String},
    {"VisibleString",     TokenKind::KwVisibleString},
    {"BMPString",         TokenKind::KwBMPString},
    {"TeletexString",     TokenKind::KwTeletexString},
    {"NumericString",     TokenKind::KwNumericString},
    {"UniversalString",   TokenKind::KwUniversalString},
    {"GeneralString",     TokenKind::KwGeneralString},
    {"UTCTime",           TokenKind::KwUtcTime},
    {"GeneralizedTime",   TokenKind::KwGeneralizedTime},
};

constexpr auto classify_identifier(std::string_view text) -> TokenKind {
    for (auto& [kw, kind] : keywords) {
        if (kw == text) return kind;
    }
    return TokenKind::Identifier;
}

constexpr bool is_alpha(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

constexpr bool is_digit(char c) {
    return c >= '0' && c <= '9';
}

constexpr bool is_alnum_or_dash(char c) {
    return is_alpha(c) || is_digit(c) || c == '-';
}

constexpr bool is_whitespace(char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

} // namespace detail

constexpr auto lex(std::string_view src) -> FixedVector<Token, 1024> {
    FixedVector<Token, 1024> tokens;
    std::size_t pos = 0;

    auto peek = [&]() -> char {
        return pos < src.size() ? src[pos] : '\0';
    };
    auto advance = [&]() -> char {
        return src[pos++];
    };

    while (pos < src.size()) {
        // Skip whitespace
        if (detail::is_whitespace(peek())) {
            advance();
            continue;
        }

        // Skip -- comments
        if (peek() == '-' && pos + 1 < src.size() && src[pos + 1] == '-') {
            pos += 2;
            while (pos < src.size() && src[pos] != '\n')
                ++pos;
            continue;
        }

        Token tok;

        // ::=
        if (peek() == ':' && pos + 2 < src.size() && src[pos + 1] == ':' && src[pos + 2] == '=') {
            tok.kind = TokenKind::Assignment;
            tok.text = "::=";
            pos += 3;
            tokens.push_back(tok);
            continue;
        }

        // ..
        if (peek() == '.' && pos + 1 < src.size() && src[pos + 1] == '.') {
            tok.kind = TokenKind::DotDot;
            tok.text = "..";
            pos += 2;
            tokens.push_back(tok);
            continue;
        }

        // Single-char tokens
        char c = peek();
        if (c == '{') { tok.kind = TokenKind::LBrace;    tok.text = "{"; advance(); tokens.push_back(tok); continue; }
        if (c == '}') { tok.kind = TokenKind::RBrace;    tok.text = "}"; advance(); tokens.push_back(tok); continue; }
        if (c == '[') { tok.kind = TokenKind::LBracket;  tok.text = "["; advance(); tokens.push_back(tok); continue; }
        if (c == ']') { tok.kind = TokenKind::RBracket;  tok.text = "]"; advance(); tokens.push_back(tok); continue; }
        if (c == '(') { tok.kind = TokenKind::LParen;    tok.text = "("; advance(); tokens.push_back(tok); continue; }
        if (c == ')') { tok.kind = TokenKind::RParen;    tok.text = ")"; advance(); tokens.push_back(tok); continue; }
        if (c == ',') { tok.kind = TokenKind::Comma;     tok.text = ","; advance(); tokens.push_back(tok); continue; }
        if (c == ';') { tok.kind = TokenKind::Semicolon; tok.text = ";"; advance(); tokens.push_back(tok); continue; }
        if (c == '.') { tok.kind = TokenKind::Dot;       tok.text = "."; advance(); tokens.push_back(tok); continue; }
        if (c == '|') { tok.kind = TokenKind::Pipe;      tok.text = "|"; advance(); tokens.push_back(tok); continue; }

        // Numbers
        if (detail::is_digit(c)) {
            std::size_t start = pos;
            while (pos < src.size() && detail::is_digit(src[pos]))
                ++pos;
            tok.kind = TokenKind::Number;
            tok.text = src.substr(start, pos - start);
            tokens.push_back(tok);
            continue;
        }

        // Identifiers and keywords
        if (detail::is_alpha(c)) {
            std::size_t start = pos;
            while (pos < src.size() && detail::is_alnum_or_dash(src[pos]))
                ++pos;
            // Trim trailing dashes (shouldn't appear, but be safe)
            while (pos > start && src[pos - 1] == '-')
                --pos;

            auto text = src.substr(start, pos - start);
            auto kind = detail::classify_identifier(text);

            // Handle multi-word keywords: BIT STRING, OCTET STRING, OBJECT IDENTIFIER
            if (kind == TokenKind::KwBitString || kind == TokenKind::KwOctetString ||
                kind == TokenKind::KwObjectIdentifier) {
                // Look ahead for the second word
                std::size_t saved = pos;
                while (pos < src.size() && detail::is_whitespace(src[pos]))
                    ++pos;
                std::size_t start2 = pos;
                if (pos < src.size() && detail::is_alpha(src[pos])) {
                    while (pos < src.size() && detail::is_alnum_or_dash(src[pos]))
                        ++pos;
                    auto word2 = src.substr(start2, pos - start2);
                    if ((kind == TokenKind::KwBitString && word2 == "STRING") ||
                        (kind == TokenKind::KwOctetString && word2 == "STRING") ||
                        (kind == TokenKind::KwObjectIdentifier && word2 == "IDENTIFIER")) {
                        tok.kind = kind;
                        tok.text = (kind == TokenKind::KwBitString)        ? FixedString<64>{"BIT STRING"} :
                                   (kind == TokenKind::KwOctetString)      ? FixedString<64>{"OCTET STRING"} :
                                                                             FixedString<64>{"OBJECT IDENTIFIER"};
                        tokens.push_back(tok);
                        continue;
                    }
                }
                // Not a multi-word keyword, backtrack
                pos = saved;
                kind = TokenKind::Identifier;
            }

            tok.kind = kind;
            tok.text = text;
            tokens.push_back(tok);
            continue;
        }

        // Quoted string
        if (c == '"') {
            advance(); // skip opening quote
            std::size_t start = pos;
            while (pos < src.size() && src[pos] != '"')
                ++pos;
            tok.kind = TokenKind::String;
            tok.text = src.substr(start, pos - start);
            if (pos < src.size()) ++pos; // skip closing quote
            tokens.push_back(tok);
            continue;
        }

        // Unknown character - skip
        advance();
    }

    Token eof;
    eof.kind = TokenKind::Eof;
    tokens.push_back(eof);
    return tokens;
}

} // namespace asn1
