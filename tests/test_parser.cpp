#include <asn1/parser.hpp>

using namespace asn1;

// Test: parse a simple SEQUENCE
constexpr auto simple_mod = parse_module(
    "Test DEFINITIONS EXPLICIT TAGS ::= BEGIN\n"
    "Foo ::= SEQUENCE {\n"
    "    bar  INTEGER,\n"
    "    baz  OCTET STRING\n"
    "}\n"
    "END\n"
);

static_assert(simple_mod.name.view() == "Test");
static_assert(simple_mod.default_tag_mode == TagMode::Explicit);
static_assert(simple_mod.types.size() == 1);
static_assert(simple_mod.types[0].name.view() == "Foo");

// Check the Sequence node
constexpr auto& foo_node = simple_mod.nodes[simple_mod.types[0].node_index];
static_assert(foo_node.kind == AstNodeKind::Sequence);
static_assert(foo_node.fields.size() == 2);
static_assert(foo_node.fields[0].name.view() == "bar");
static_assert(foo_node.fields[1].name.view() == "baz");

// Check field types
constexpr auto& bar_type = simple_mod.nodes[foo_node.fields[0].type_index];
static_assert(bar_type.kind == AstNodeKind::Integer);
constexpr auto& baz_type = simple_mod.nodes[foo_node.fields[1].type_index];
static_assert(baz_type.kind == AstNodeKind::OctetString);

// Test: parse OPTIONAL and tagged fields
constexpr auto tagged_mod = parse_module(
    "Test DEFINITIONS IMPLICIT TAGS ::= BEGIN\n"
    "Bar ::= SEQUENCE {\n"
    "    x  INTEGER,\n"
    "    y  [0] EXPLICIT BIT STRING OPTIONAL,\n"
    "    z  [1] OCTET STRING OPTIONAL\n"
    "}\n"
    "END\n"
);

static_assert(tagged_mod.default_tag_mode == TagMode::Implicit);
constexpr auto& bar_node = tagged_mod.nodes[tagged_mod.types[0].node_index];
static_assert(bar_node.fields.size() == 3);
static_assert(bar_node.fields[1].optional == true);
static_assert(bar_node.fields[2].optional == true);

// Field y should be Tagged with explicit
constexpr auto& y_type = tagged_mod.nodes[bar_node.fields[1].type_index];
static_assert(y_type.kind == AstNodeKind::Tagged);
static_assert(y_type.tag_number == 0);
static_assert(y_type.tag_mode == TagMode::Explicit);

// Field z: tagged [1], no explicit/implicit keyword -> module default (implicit)
constexpr auto& z_type = tagged_mod.nodes[bar_node.fields[2].type_index];
static_assert(z_type.kind == AstNodeKind::Tagged);
static_assert(z_type.tag_number == 1);
static_assert(z_type.tag_mode == TagMode::Implicit);

// Test: parse CHOICE
constexpr auto choice_mod = parse_module(
    "Test DEFINITIONS EXPLICIT TAGS ::= BEGIN\n"
    "Params ::= CHOICE {\n"
    "    namedCurve  OBJECT IDENTIFIER\n"
    "}\n"
    "END\n"
);

constexpr auto& params_node = choice_mod.nodes[choice_mod.types[0].node_index];
static_assert(params_node.kind == AstNodeKind::Choice);
static_assert(params_node.fields.size() == 1);
static_assert(params_node.fields[0].name.view() == "namedCurve");

// Test: parse type references
constexpr auto ref_mod = parse_module(
    "Test DEFINITIONS EXPLICIT TAGS ::= BEGIN\n"
    "Inner ::= INTEGER\n"
    "Outer ::= SEQUENCE {\n"
    "    field  Inner\n"
    "}\n"
    "END\n"
);

static_assert(ref_mod.types.size() == 2);
constexpr auto& outer_node = ref_mod.nodes[ref_mod.types[1].node_index];
constexpr auto& field_type = ref_mod.nodes[outer_node.fields[0].type_index];
static_assert(field_type.kind == AstNodeKind::TypeRef);
static_assert(field_type.name.view() == "Inner");

// Test: INTEGER with named numbers
constexpr auto named_int_mod = parse_module(
    "Test DEFINITIONS EXPLICIT TAGS ::= BEGIN\n"
    "Version ::= INTEGER { v1(0), v2(1) }\n"
    "END\n"
);

constexpr auto& ver_node = named_int_mod.nodes[named_int_mod.types[0].node_index];
static_assert(ver_node.kind == AstNodeKind::Integer);
static_assert(ver_node.named_numbers.size() == 2);
static_assert(ver_node.named_numbers[0].name.view() == "v1");
static_assert(ver_node.named_numbers[0].value == 0);
static_assert(ver_node.named_numbers[1].name.view() == "v2");
static_assert(ver_node.named_numbers[1].value == 1);

// Test: ANY DEFINED BY
constexpr auto any_mod = parse_module(
    "Test DEFINITIONS EXPLICIT TAGS ::= BEGIN\n"
    "AlgId ::= SEQUENCE {\n"
    "    algorithm   OBJECT IDENTIFIER,\n"
    "    parameters  ANY DEFINED BY algorithm OPTIONAL\n"
    "}\n"
    "END\n"
);

constexpr auto& algid_node = any_mod.nodes[any_mod.types[0].node_index];
static_assert(algid_node.fields.size() == 2);
static_assert(algid_node.fields[1].optional == true);
constexpr auto& params_type = any_mod.nodes[algid_node.fields[1].type_index];
static_assert(params_type.kind == AstNodeKind::AnyDefinedBy);
static_assert(params_type.defined_by.view() == "algorithm");

// Test: DEFAULT value
constexpr auto default_mod = parse_module(
    "Test DEFINITIONS EXPLICIT TAGS ::= BEGIN\n"
    "Foo ::= SEQUENCE {\n"
    "    version INTEGER DEFAULT 0\n"
    "}\n"
    "END\n"
);

constexpr auto& dflt_node = default_mod.nodes[default_mod.types[0].node_index];
static_assert(dflt_node.fields[0].has_default == true);
static_assert(dflt_node.fields[0].default_int == 0);

// Test: find_type helper
static_assert(simple_mod.find_type("Foo") != static_cast<std::size_t>(-1));
static_assert(simple_mod.find_type("Nonexistent") == static_cast<std::size_t>(-1));

// Test: IMPORTS are skipped
constexpr auto import_mod = parse_module(
    "Test DEFINITIONS EXPLICIT TAGS ::= BEGIN\n"
    "IMPORTS Foo, Bar FROM OtherModule;\n"
    "Baz ::= INTEGER\n"
    "END\n"
);

static_assert(import_mod.types.size() == 1);
static_assert(import_mod.types[0].name.view() == "Baz");

// Test: parse the full ECC definitions via #embed
constexpr char ecc_asn1[] = {
    #embed "definitions/ecprivatekey.asn1"
};

constexpr auto ecc_mod = parse_module(std::string_view{ecc_asn1, sizeof(ecc_asn1)});

static_assert(ecc_mod.name.view() == "ECCKeyStructures");
static_assert(ecc_mod.default_tag_mode == TagMode::Explicit);

// Check that all expected types were parsed
static_assert(ecc_mod.find_type("AlgorithmIdentifier") != static_cast<std::size_t>(-1));
static_assert(ecc_mod.find_type("SubjectPublicKeyInfo") != static_cast<std::size_t>(-1));
static_assert(ecc_mod.find_type("ECParameters") != static_cast<std::size_t>(-1));
static_assert(ecc_mod.find_type("ECPrivateKey") != static_cast<std::size_t>(-1));
static_assert(ecc_mod.find_type("OneAsymmetricKey") != static_cast<std::size_t>(-1));
static_assert(ecc_mod.find_type("ECDSA-Sig-Value") != static_cast<std::size_t>(-1));

// Verify ECPrivateKey structure
constexpr auto& ecpk = ecc_mod.nodes[ecc_mod.find_type("ECPrivateKey")];
static_assert(ecpk.kind == AstNodeKind::Sequence);
static_assert(ecpk.fields.size() == 4);
static_assert(ecpk.fields[0].name.view() == "version");
static_assert(ecpk.fields[1].name.view() == "privateKey");
static_assert(ecpk.fields[2].name.view() == "parameters");
static_assert(ecpk.fields[2].optional == true);
static_assert(ecpk.fields[3].name.view() == "publicKey");
static_assert(ecpk.fields[3].optional == true);

// Verify ECDSA-Sig-Value
constexpr auto& sig = ecc_mod.nodes[ecc_mod.find_type("ECDSA-Sig-Value")];
static_assert(sig.kind == AstNodeKind::Sequence);
static_assert(sig.fields.size() == 2);
static_assert(sig.fields[0].name.view() == "r");
static_assert(sig.fields[1].name.view() == "s");

int main() {
    return 0;
}
