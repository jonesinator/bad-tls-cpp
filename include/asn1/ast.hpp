#pragma once

#include <asn1/fixed_string.hpp>
#include <asn1/fixed_vector.hpp>
#include <cstdint>
#include <string_view>

namespace asn1 {

enum class AstNodeKind : uint8_t {
    // Primitive types
    Integer,
    Boolean,
    Null,
    BitString,
    OctetString,
    ObjectIdentifier,
    Enumerated,

    // String types
    Utf8String,
    PrintableString,
    IA5String,
    VisibleString,
    BMPString,
    TeletexString,
    NumericString,
    UniversalString,
    GeneralString,

    // Time types
    UtcTime,
    GeneralizedTime,

    // Constructed types
    Sequence,
    SequenceOf,
    SetOf,
    Choice,

    // Modifiers
    Tagged,
    TypeRef,
    AnyDefinedBy,
};

enum class TagClass : uint8_t {
    Universal,
    Application,
    ContextSpecific,
    Private,
};

enum class TagMode : uint8_t {
    Explicit,
    Implicit,
    Automatic,
};

struct AstField {
    FixedString<64> name{};
    std::size_t type_index = 0;
    bool optional = false;
    bool has_default = false;
    int64_t default_int = 0;

    constexpr bool operator==(const AstField&) const = default;
};

struct NamedNumber {
    FixedString<64> name{};
    int64_t value = 0;

    constexpr bool operator==(const NamedNumber&) const = default;
};

struct AstNode {
    AstNodeKind kind{};
    FixedString<64> name{};

    // SEQUENCE / CHOICE fields
    FixedVector<AstField, 24> fields{};

    // INTEGER named numbers
    FixedVector<NamedNumber, 8> named_numbers{};

    // Tagged type
    TagClass tag_class = TagClass::ContextSpecific;
    TagMode tag_mode = TagMode::Explicit;
    uint32_t tag_number = 0;

    // Inner type index (Tagged, SequenceOf, SetOf)
    std::size_t inner_index = 0;

    // ANY DEFINED BY discriminant field name
    FixedString<64> defined_by{};

    constexpr bool operator==(const AstNode&) const = default;
};

struct TypeAssignment {
    FixedString<64> name{};
    std::size_t node_index = 0;

    constexpr bool operator==(const TypeAssignment&) const = default;
};

struct ValueAssignment {
    FixedString<64> name{};
    FixedString<64> type_name{};
    FixedVector<uint32_t, 16> oid_components{};
    // Named OID components (references to other values)
    FixedVector<FixedString<64>, 16> oid_names{};

    constexpr bool operator==(const ValueAssignment&) const = default;
};

struct AstModule {
    FixedString<128> name{};
    TagMode default_tag_mode = TagMode::Explicit;
    FixedVector<AstNode, 128> nodes{};
    FixedVector<TypeAssignment, 32> types{};
    FixedVector<ValueAssignment, 32> values{};

    constexpr auto add_node(AstNode node) -> std::size_t {
        auto idx = nodes.size();
        nodes.push_back(node);
        return idx;
    }

    constexpr auto find_type(std::string_view n) const -> std::size_t {
        for (std::size_t i = 0; i < types.size(); ++i) {
            if (types[i].name.view() == n)
                return types[i].node_index;
        }
        return static_cast<std::size_t>(-1);
    }

    constexpr bool operator==(const AstModule&) const = default;
};

} // namespace asn1
