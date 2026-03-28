#pragma once

#include <asn1/ast.hpp>
#include <cstdint>

namespace asn1::der {

// Tag class bits (high 2 bits of tag byte)
inline constexpr uint8_t ClassUniversal        = 0x00;
inline constexpr uint8_t ClassApplication      = 0x40;
inline constexpr uint8_t ClassContextSpecific  = 0x80;
inline constexpr uint8_t ClassPrivate          = 0xC0;

// Constructed bit
inline constexpr uint8_t Constructed = 0x20;

// Universal tag numbers
inline constexpr uint8_t TagBoolean     = 0x01;
inline constexpr uint8_t TagInteger     = 0x02;
inline constexpr uint8_t TagBitString   = 0x03;
inline constexpr uint8_t TagOctetString = 0x04;
inline constexpr uint8_t TagNull        = 0x05;
inline constexpr uint8_t TagOID         = 0x06;
inline constexpr uint8_t TagEnumerated  = 0x0A;
inline constexpr uint8_t TagSequence    = 0x30; // Universal 16 | Constructed
inline constexpr uint8_t TagSet         = 0x31; // Universal 17 | Constructed

constexpr auto to_der_class(TagClass c) -> uint8_t {
    switch (c) {
        case TagClass::Universal:       return ClassUniversal;
        case TagClass::Application:     return ClassApplication;
        case TagClass::ContextSpecific: return ClassContextSpecific;
        case TagClass::Private:         return ClassPrivate;
    }
    return ClassContextSpecific;
}

constexpr auto universal_tag_number(AstNodeKind kind) -> uint32_t {
    switch (kind) {
        case AstNodeKind::Boolean:          return 0x01;
        case AstNodeKind::Integer:          return 0x02;
        case AstNodeKind::Enumerated:       return 0x0A;
        case AstNodeKind::BitString:        return 0x03;
        case AstNodeKind::OctetString:      return 0x04;
        case AstNodeKind::Null:             return 0x05;
        case AstNodeKind::ObjectIdentifier: return 0x06;
        case AstNodeKind::Sequence:         return 0x10;
        case AstNodeKind::SequenceOf:       return 0x10;
        case AstNodeKind::SetOf:            return 0x11;
        default:                            return 0;
    }
}

constexpr auto is_constructed_kind(AstNodeKind kind) -> bool {
    switch (kind) {
        case AstNodeKind::Sequence:
        case AstNodeKind::SequenceOf:
        case AstNodeKind::SetOf:
        case AstNodeKind::Choice:
            return true;
        default:
            return false;
    }
}

// Expected tag for an AST node — used by SEQUENCE decoder to peek-match fields
struct ExpectedTag {
    uint8_t class_bits = ClassUniversal;
    bool constructed = false;
    uint32_t number = 0;
};

template <auto M, std::size_t I>
consteval auto expected_tag() -> ExpectedTag {
    constexpr auto& node = M.nodes[I];

    if constexpr (node.kind == AstNodeKind::Tagged) {
        // Tagged types have their own tag
        constexpr bool inner_constr = is_constructed_kind(M.nodes[node.inner_index].kind);
        if constexpr (node.tag_mode == TagMode::Explicit) {
            // EXPLICIT is always constructed (it wraps the inner TLV)
            return {to_der_class(node.tag_class), true, node.tag_number};
        } else {
            // IMPLICIT: preserves constructed bit from inner type
            return {to_der_class(node.tag_class), inner_constr, node.tag_number};
        }
    } else if constexpr (node.kind == AstNodeKind::TypeRef) {
        return expected_tag<M, M.find_type(node.name.view())>();
    } else if constexpr (node.kind == AstNodeKind::AnyDefinedBy) {
        // ANY can be anything — return a sentinel; caller must handle specially
        return {0xFF, false, 0};
    } else {
        return {
            ClassUniversal,
            is_constructed_kind(node.kind),
            universal_tag_number(node.kind)
        };
    }
}

} // namespace asn1::der
