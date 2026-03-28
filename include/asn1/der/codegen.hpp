#pragma once

#include <asn1/ast.hpp>
#include <asn1/der/reader.hpp>
#include <asn1/der/tag.hpp>
#include <asn1/der/types.hpp>
#include <asn1/der/writer.hpp>
#include <asn1/fixed_string.hpp>
#include <cstddef>
#include <optional>
#include <tuple>
#include <variant>
#include <vector>

namespace asn1::der {

// Forward declarations
template <auto M, std::size_t I> struct Resolve;
template <auto M, std::size_t I> using Mapped = typename Resolve<M, I>::type;
template <auto M, std::size_t I> struct SequenceType;
template <auto M, std::size_t I> struct ChoiceType;

// --- Type Resolution (requires-clause specializations) ---

template <auto M, std::size_t I>
    requires (M.nodes[I].kind == AstNodeKind::Integer ||
              M.nodes[I].kind == AstNodeKind::Enumerated)
struct Resolve<M, I> { using type = Integer; };

template <auto M, std::size_t I>
    requires (M.nodes[I].kind == AstNodeKind::Boolean)
struct Resolve<M, I> { using type = Boolean; };

template <auto M, std::size_t I>
    requires (M.nodes[I].kind == AstNodeKind::Null)
struct Resolve<M, I> { using type = Null; };

template <auto M, std::size_t I>
    requires (M.nodes[I].kind == AstNodeKind::BitString)
struct Resolve<M, I> { using type = BitString; };

template <auto M, std::size_t I>
    requires (M.nodes[I].kind == AstNodeKind::OctetString)
struct Resolve<M, I> { using type = OctetString; };

// String and time types all map to OctetString (raw bytes, no charset validation)
template <auto M, std::size_t I>
    requires (M.nodes[I].kind == AstNodeKind::Utf8String ||
              M.nodes[I].kind == AstNodeKind::PrintableString ||
              M.nodes[I].kind == AstNodeKind::IA5String ||
              M.nodes[I].kind == AstNodeKind::VisibleString ||
              M.nodes[I].kind == AstNodeKind::BMPString ||
              M.nodes[I].kind == AstNodeKind::TeletexString ||
              M.nodes[I].kind == AstNodeKind::NumericString ||
              M.nodes[I].kind == AstNodeKind::UniversalString ||
              M.nodes[I].kind == AstNodeKind::GeneralString ||
              M.nodes[I].kind == AstNodeKind::UtcTime ||
              M.nodes[I].kind == AstNodeKind::GeneralizedTime)
struct Resolve<M, I> { using type = OctetString; };

template <auto M, std::size_t I>
    requires (M.nodes[I].kind == AstNodeKind::ObjectIdentifier)
struct Resolve<M, I> { using type = ObjectIdentifier; };

template <auto M, std::size_t I>
    requires (M.nodes[I].kind == AstNodeKind::AnyDefinedBy)
struct Resolve<M, I> { using type = AnyValue; };

template <auto M, std::size_t I>
    requires (M.nodes[I].kind == AstNodeKind::Tagged)
struct Resolve<M, I> { using type = Mapped<M, M.nodes[I].inner_index>; };

template <auto M, std::size_t I>
    requires (M.nodes[I].kind == AstNodeKind::TypeRef)
struct Resolve<M, I> { using type = Mapped<M, M.find_type(M.nodes[I].name.view())>; };

template <auto M, std::size_t I>
    requires (M.nodes[I].kind == AstNodeKind::SequenceOf ||
              M.nodes[I].kind == AstNodeKind::SetOf)
struct Resolve<M, I> { using type = std::vector<Mapped<M, M.nodes[I].inner_index>>; };

template <auto M, std::size_t I>
    requires (M.nodes[I].kind == AstNodeKind::Sequence)
struct Resolve<M, I> { using type = SequenceType<M, I>; };

template <auto M, std::size_t I>
    requires (M.nodes[I].kind == AstNodeKind::Choice)
struct Resolve<M, I> { using type = ChoiceType<M, I>; };

// --- SequenceType ---

// Helper: compute the C++ type for a single SEQUENCE field
template <auto M, std::size_t NodeIdx, std::size_t FieldIdx>
struct FieldTypeHelper {
    static constexpr auto& field = M.nodes[NodeIdx].fields[FieldIdx];
    using raw = Mapped<M, field.type_index>;
    using type = std::conditional_t<field.optional || field.has_default,
                                    std::optional<raw>, raw>;
};

// Helper: build the tuple type from an index sequence
template <auto M, std::size_t NodeIdx, typename Seq>
struct FieldsTupleHelper;

template <auto M, std::size_t NodeIdx, std::size_t... Js>
struct FieldsTupleHelper<M, NodeIdx, std::index_sequence<Js...>> {
    using type = std::tuple<typename FieldTypeHelper<M, NodeIdx, Js>::type...>;
};

template <auto M, std::size_t I>
struct SequenceType {
    static constexpr auto& node = M.nodes[I];
    static constexpr auto field_count = node.fields.size();

    using FieldsTuple = typename FieldsTupleHelper<
        M, I, std::make_index_sequence<field_count>>::type;
    FieldsTuple fields{};

    template <FixedString<64> Name>
    static consteval auto field_index() -> std::size_t {
        for (std::size_t i = 0; i < field_count; ++i)
            if (node.fields[i].name.view() == Name.view())
                return i;
        // Will produce compile error in consteval context
        throw "field not found";
    }

    template <FixedString<64> Name>
    auto& get() { return std::get<field_index<Name>()>(fields); }

    template <FixedString<64> Name>
    const auto& get() const { return std::get<field_index<Name>()>(fields); }

    bool operator==(const SequenceType&) const = default;
};

// --- ChoiceType ---

template <auto M, std::size_t NodeIdx, typename Seq>
struct ChoiceVariantHelper;

template <auto M, std::size_t NodeIdx, std::size_t... Js>
struct ChoiceVariantHelper<M, NodeIdx, std::index_sequence<Js...>> {
    using type = std::variant<Mapped<M, M.nodes[NodeIdx].fields[Js].type_index>...>;
};

template <auto M, std::size_t I>
struct ChoiceType {
    static constexpr auto& node = M.nodes[I];
    static constexpr auto alt_count = node.fields.size();

    using VariantType = typename ChoiceVariantHelper<
        M, I, std::make_index_sequence<alt_count>>::type;
    VariantType value{};

    template <FixedString<64> Name>
    static consteval auto alt_index() -> std::size_t {
        for (std::size_t i = 0; i < alt_count; ++i)
            if (node.fields[i].name.view() == Name.view())
                return i;
        throw "alternative not found";
    }

    template <FixedString<64> Name>
    auto& as() { return std::get<alt_index<Name>()>(value); }

    template <FixedString<64> Name>
    const auto& as() const { return std::get<alt_index<Name>()>(value); }

    template <FixedString<64> Name>
    void set(Mapped<M, node.fields[alt_index<Name>()].type_index> v) {
        value.template emplace<alt_index<Name>()>(std::move(v));
    }

    bool operator==(const ChoiceType&) const = default;
};

// --- Convenience alias ---

template <auto M, FixedString<64> Name>
using Type = Mapped<M, M.find_type(Name.view())>;

// --- Encode ---

template <auto M, std::size_t I>
void encode(Writer& w, const Mapped<M, I>& value);

// Encode a single SEQUENCE field
template <auto M, std::size_t NodeIdx, std::size_t FieldIdx>
void encode_field(Writer& w, const SequenceType<M, NodeIdx>& seq) {
    constexpr auto& field = M.nodes[NodeIdx].fields[FieldIdx];
    const auto& val = std::get<FieldIdx>(seq.fields);

    if constexpr (field.optional || field.has_default) {
        if (val.has_value())
            encode<M, field.type_index>(w, *val);
    } else {
        encode<M, field.type_index>(w, val);
    }
}

// Encode all SEQUENCE fields via fold expression
template <auto M, std::size_t NodeIdx, std::size_t... Js>
void encode_fields(Writer& w, const SequenceType<M, NodeIdx>& seq,
                   std::index_sequence<Js...>) {
    (encode_field<M, NodeIdx, Js>(w, seq), ...);
}

// Encode a single CHOICE alternative (try one)
template <auto M, std::size_t NodeIdx, std::size_t AltIdx>
bool encode_choice_alt(Writer& w, const ChoiceType<M, NodeIdx>& ch) {
    if (ch.value.index() == AltIdx) {
        constexpr auto& field = M.nodes[NodeIdx].fields[AltIdx];
        encode<M, field.type_index>(w, std::get<AltIdx>(ch.value));
        return true;
    }
    return false;
}

template <auto M, std::size_t NodeIdx, std::size_t... Js>
void encode_choice(Writer& w, const ChoiceType<M, NodeIdx>& ch,
                   std::index_sequence<Js...>) {
    (encode_choice_alt<M, NodeIdx, Js>(w, ch) || ...);
}

template <auto M, std::size_t I>
void encode(Writer& w, const Mapped<M, I>& value) {
    constexpr auto& node = M.nodes[I];

    if constexpr (node.kind == AstNodeKind::Integer ||
                  node.kind == AstNodeKind::Enumerated) {
        if constexpr (node.kind == AstNodeKind::Enumerated)
            w.write(value, TagEnumerated);
        else
            w.write(value);
    }
    else if constexpr (node.kind == AstNodeKind::Boolean) {
        w.write(value);
    }
    else if constexpr (node.kind == AstNodeKind::Null) {
        w.write(value);
    }
    else if constexpr (node.kind == AstNodeKind::BitString) {
        w.write(value);
    }
    else if constexpr (node.kind == AstNodeKind::OctetString) {
        w.write(value);
    }
    else if constexpr (node.kind == AstNodeKind::Utf8String ||
                       node.kind == AstNodeKind::PrintableString ||
                       node.kind == AstNodeKind::IA5String ||
                       node.kind == AstNodeKind::VisibleString ||
                       node.kind == AstNodeKind::BMPString ||
                       node.kind == AstNodeKind::TeletexString ||
                       node.kind == AstNodeKind::NumericString ||
                       node.kind == AstNodeKind::UniversalString ||
                       node.kind == AstNodeKind::GeneralString ||
                       node.kind == AstNodeKind::UtcTime ||
                       node.kind == AstNodeKind::GeneralizedTime) {
        w.write(value, universal_tag_number(node.kind));
    }
    else if constexpr (node.kind == AstNodeKind::ObjectIdentifier) {
        w.write(value);
    }
    else if constexpr (node.kind == AstNodeKind::AnyDefinedBy) {
        w.write(value);
    }
    else if constexpr (node.kind == AstNodeKind::Tagged) {
        if constexpr (node.tag_mode == TagMode::Explicit) {
            uint8_t tag_byte = to_der_class(node.tag_class) | Constructed |
                               static_cast<uint8_t>(node.tag_number);
            w.write_constructed(tag_byte, [&](Writer& inner) {
                encode<M, node.inner_index>(inner, value);
            });
        } else {
            // Implicit: encode inner value bytes with overridden tag
            constexpr bool inner_constr = is_constructed_kind(
                M.nodes[node.inner_index].kind);
            uint8_t tag_byte = to_der_class(node.tag_class) |
                               (inner_constr ? Constructed : uint8_t{0}) |
                               static_cast<uint8_t>(node.tag_number);
            encode_implicit<M, node.inner_index>(w, value, tag_byte);
        }
    }
    else if constexpr (node.kind == AstNodeKind::TypeRef) {
        constexpr auto resolved = M.find_type(node.name.view());
        encode<M, resolved>(w, value);
    }
    else if constexpr (node.kind == AstNodeKind::Sequence) {
        w.write_constructed(TagSequence, [&](Writer& inner) {
            encode_fields<M, I>(inner, value,
                std::make_index_sequence<node.fields.size()>{});
        });
    }
    else if constexpr (node.kind == AstNodeKind::Choice) {
        encode_choice<M, I>(w, value,
            std::make_index_sequence<node.fields.size()>{});
    }
    else if constexpr (node.kind == AstNodeKind::SequenceOf) {
        w.write_constructed(TagSequence, [&](Writer& inner) {
            for (const auto& elem : value)
                encode<M, node.inner_index>(inner, elem);
        });
    }
    else if constexpr (node.kind == AstNodeKind::SetOf) {
        w.write_constructed(TagSet, [&](Writer& inner) {
            for (const auto& elem : value)
                encode<M, node.inner_index>(inner, elem);
        });
    }
}

// Implicit tag encoding: writes inner value with overridden tag
template <auto M, std::size_t InnerIdx>
void encode_implicit(Writer& w, const Mapped<M, InnerIdx>& value, uint8_t tag) {
    constexpr auto& inner = M.nodes[InnerIdx];

    if constexpr (inner.kind == AstNodeKind::Integer ||
                  inner.kind == AstNodeKind::Enumerated) {
        w.write(value, tag);
    }
    else if constexpr (inner.kind == AstNodeKind::Boolean) {
        w.write(value, tag);
    }
    else if constexpr (inner.kind == AstNodeKind::Null) {
        w.write(value, tag);
    }
    else if constexpr (inner.kind == AstNodeKind::BitString) {
        w.write(value, tag);
    }
    else if constexpr (inner.kind == AstNodeKind::OctetString ||
                       inner.kind == AstNodeKind::Utf8String ||
                       inner.kind == AstNodeKind::PrintableString ||
                       inner.kind == AstNodeKind::IA5String ||
                       inner.kind == AstNodeKind::VisibleString ||
                       inner.kind == AstNodeKind::BMPString ||
                       inner.kind == AstNodeKind::TeletexString ||
                       inner.kind == AstNodeKind::NumericString ||
                       inner.kind == AstNodeKind::UniversalString ||
                       inner.kind == AstNodeKind::GeneralString ||
                       inner.kind == AstNodeKind::UtcTime ||
                       inner.kind == AstNodeKind::GeneralizedTime) {
        w.write(value, tag);
    }
    else if constexpr (inner.kind == AstNodeKind::ObjectIdentifier) {
        w.write(value, tag);
    }
    else if constexpr (inner.kind == AstNodeKind::Sequence) {
        w.write_constructed(tag, [&](Writer& inner_w) {
            encode_fields<M, InnerIdx>(inner_w, value,
                std::make_index_sequence<inner.fields.size()>{});
        });
    }
    else if constexpr (inner.kind == AstNodeKind::SequenceOf) {
        w.write_constructed(tag, [&](Writer& inner_w) {
            for (const auto& elem : value)
                encode<M, inner.inner_index>(inner_w, elem);
        });
    }
    else if constexpr (inner.kind == AstNodeKind::SetOf) {
        w.write_constructed(tag, [&](Writer& inner_w) {
            for (const auto& elem : value)
                encode<M, inner.inner_index>(inner_w, elem);
        });
    }
    else if constexpr (inner.kind == AstNodeKind::TypeRef) {
        constexpr auto resolved = M.find_type(inner.name.view());
        encode_implicit<M, resolved>(w, value, tag);
    }
    else {
        // Fallback: encode normally then replace tag (shouldn't reach here)
        w.write(value, tag);
    }
}

// --- Decode ---

template <auto M, std::size_t I>
auto decode(Reader& r) -> Mapped<M, I>;

// Resolve the actual inner node index, skipping TypeRef chains
template <auto M, std::size_t I>
consteval auto resolve_inner() -> std::size_t {
    constexpr auto& node = M.nodes[I];
    if constexpr (node.kind == AstNodeKind::TypeRef)
        return resolve_inner<M, M.find_type(node.name.view())>();
    else
        return I;
}

// Decode a single SEQUENCE field
template <auto M, std::size_t NodeIdx, std::size_t FieldIdx>
void decode_field(Reader& r, SequenceType<M, NodeIdx>& seq) {
    constexpr auto& field = M.nodes[NodeIdx].fields[FieldIdx];
    constexpr auto exp = expected_tag<M, field.type_index>();

    if constexpr (field.optional || field.has_default) {
        if (!r.at_end()) {
            // ANY matches anything
            if constexpr (exp.class_bits == 0xFF) {
                std::get<FieldIdx>(seq.fields) = decode<M, field.type_index>(r);
            } else if (r.peek_matches(exp.class_bits, exp.number)) {
                std::get<FieldIdx>(seq.fields) = decode<M, field.type_index>(r);
            }
        }
    } else {
        std::get<FieldIdx>(seq.fields) = decode<M, field.type_index>(r);
    }
}

template <auto M, std::size_t NodeIdx, std::size_t... Js>
void decode_fields(Reader& r, SequenceType<M, NodeIdx>& seq,
                   std::index_sequence<Js...>) {
    (decode_field<M, NodeIdx, Js>(r, seq), ...);
}

// Decode CHOICE by trying alternatives
template <auto M, std::size_t NodeIdx, std::size_t AltIdx>
bool decode_choice_alt(Reader& r, ChoiceType<M, NodeIdx>& ch) {
    constexpr auto& field = M.nodes[NodeIdx].fields[AltIdx];
    constexpr auto exp = expected_tag<M, field.type_index>();
    if constexpr (exp.class_bits == 0xFF) {
        // ANY matches anything — use as last resort
        ch.value.template emplace<AltIdx>(decode<M, field.type_index>(r));
        return true;
    } else {
        if (r.peek_matches(exp.class_bits, exp.number)) {
            ch.value.template emplace<AltIdx>(decode<M, field.type_index>(r));
            return true;
        }
        return false;
    }
}

template <auto M, std::size_t NodeIdx, std::size_t... Js>
void decode_choice(Reader& r, ChoiceType<M, NodeIdx>& ch,
                   std::index_sequence<Js...>) {
    bool matched = (decode_choice_alt<M, NodeIdx, Js>(r, ch) || ...);
    if (!matched)
        throw DecodeError{"no CHOICE alternative matched"};
}

template <auto M, std::size_t I>
auto decode(Reader& r) -> Mapped<M, I> {
    constexpr auto& node = M.nodes[I];

    if constexpr (node.kind == AstNodeKind::Integer ||
                  node.kind == AstNodeKind::Enumerated) {
        return r.read_integer();
    }
    else if constexpr (node.kind == AstNodeKind::Boolean) {
        return r.read_boolean();
    }
    else if constexpr (node.kind == AstNodeKind::Null) {
        return r.read_null();
    }
    else if constexpr (node.kind == AstNodeKind::BitString) {
        return r.read_bit_string();
    }
    else if constexpr (node.kind == AstNodeKind::OctetString) {
        return r.read_octet_string();
    }
    else if constexpr (node.kind == AstNodeKind::Utf8String ||
                       node.kind == AstNodeKind::PrintableString ||
                       node.kind == AstNodeKind::IA5String ||
                       node.kind == AstNodeKind::VisibleString ||
                       node.kind == AstNodeKind::BMPString ||
                       node.kind == AstNodeKind::TeletexString ||
                       node.kind == AstNodeKind::NumericString ||
                       node.kind == AstNodeKind::UniversalString ||
                       node.kind == AstNodeKind::GeneralString ||
                       node.kind == AstNodeKind::UtcTime ||
                       node.kind == AstNodeKind::GeneralizedTime) {
        // Read as raw bytes (same as OctetString but with type-specific tag)
        auto hdr = r.read_header();
        auto content = r.read_content(hdr.length);
        OctetString result;
        result.bytes.assign(content.begin(), content.end());
        return result;
    }
    else if constexpr (node.kind == AstNodeKind::ObjectIdentifier) {
        return r.read_oid();
    }
    else if constexpr (node.kind == AstNodeKind::AnyDefinedBy) {
        return r.read_any();
    }
    else if constexpr (node.kind == AstNodeKind::Tagged) {
        if constexpr (node.tag_mode == TagMode::Explicit) {
            auto inner = r.enter_explicit_tag(
                to_der_class(node.tag_class), node.tag_number);
            return decode<M, node.inner_index>(inner);
        } else {
            // Implicit: read the tag (context-specific), interpret content as inner type
            return decode_implicit<M, node.inner_index>(r);
        }
    }
    else if constexpr (node.kind == AstNodeKind::TypeRef) {
        constexpr auto resolved = M.find_type(node.name.view());
        return decode<M, resolved>(r);
    }
    else if constexpr (node.kind == AstNodeKind::Sequence) {
        auto content = r.enter_sequence();
        SequenceType<M, I> result;
        decode_fields<M, I>(content, result,
            std::make_index_sequence<node.fields.size()>{});
        return result;
    }
    else if constexpr (node.kind == AstNodeKind::Choice) {
        ChoiceType<M, I> result;
        decode_choice<M, I>(r, result,
            std::make_index_sequence<node.fields.size()>{});
        return result;
    }
    else if constexpr (node.kind == AstNodeKind::SequenceOf) {
        auto content = r.enter_sequence();
        std::vector<Mapped<M, node.inner_index>> result;
        while (!content.at_end())
            result.push_back(decode<M, node.inner_index>(content));
        return result;
    }
    else if constexpr (node.kind == AstNodeKind::SetOf) {
        auto content = r.enter_set();
        std::vector<Mapped<M, node.inner_index>> result;
        while (!content.at_end())
            result.push_back(decode<M, node.inner_index>(content));
        return result;
    }
}

// Implicit tag decoding: read header (with overridden tag), interpret content
template <auto M, std::size_t InnerIdx>
auto decode_implicit(Reader& r) -> Mapped<M, InnerIdx> {
    constexpr auto& inner = M.nodes[InnerIdx];

    if constexpr (inner.kind == AstNodeKind::Integer ||
                  inner.kind == AstNodeKind::Enumerated) {
        return r.read_integer_implicit(0, 0);
    }
    else if constexpr (inner.kind == AstNodeKind::BitString) {
        return r.read_bit_string_implicit(0, 0);
    }
    else if constexpr (inner.kind == AstNodeKind::OctetString ||
                       inner.kind == AstNodeKind::Utf8String ||
                       inner.kind == AstNodeKind::PrintableString ||
                       inner.kind == AstNodeKind::IA5String ||
                       inner.kind == AstNodeKind::VisibleString ||
                       inner.kind == AstNodeKind::BMPString ||
                       inner.kind == AstNodeKind::TeletexString ||
                       inner.kind == AstNodeKind::NumericString ||
                       inner.kind == AstNodeKind::UniversalString ||
                       inner.kind == AstNodeKind::GeneralString ||
                       inner.kind == AstNodeKind::UtcTime ||
                       inner.kind == AstNodeKind::GeneralizedTime) {
        return r.read_octet_string_implicit(0, 0);
    }
    else if constexpr (inner.kind == AstNodeKind::Sequence) {
        auto h = r.read_header();
        auto content = r.scoped(h.length);
        SequenceType<M, InnerIdx> result;
        decode_fields<M, InnerIdx>(content, result,
            std::make_index_sequence<inner.fields.size()>{});
        return result;
    }
    else if constexpr (inner.kind == AstNodeKind::SequenceOf) {
        auto h = r.read_header();
        auto content = r.scoped(h.length);
        std::vector<Mapped<M, inner.inner_index>> result;
        while (!content.at_end())
            result.push_back(decode<M, inner.inner_index>(content));
        return result;
    }
    else if constexpr (inner.kind == AstNodeKind::SetOf) {
        auto h = r.read_header();
        auto content = r.scoped(h.length);
        std::vector<Mapped<M, inner.inner_index>> result;
        while (!content.at_end())
            result.push_back(decode<M, inner.inner_index>(content));
        return result;
    }
    else if constexpr (inner.kind == AstNodeKind::TypeRef) {
        constexpr auto resolved = M.find_type(inner.name.view());
        return decode_implicit<M, resolved>(r);
    }
    else {
        // Fallback: read content as raw bytes and treat as the type
        return r.read_octet_string_implicit(0, 0);
    }
}

} // namespace asn1::der
