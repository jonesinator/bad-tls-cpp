# asn1

A header-only C++26 library implementing ASN.1 parsing, DER encoding/decoding, and elliptic curve cryptography (ECC). Everything is constexpr — the entire pipeline from ASN.1 schema parsing through cryptographic operations can execute at compile time. Designed for educational purposes, prioritizing clarity over performance.

## Project Structure

```
asn1/
├── CMakeLists.txt
├── definitions/
│   └── ecprivatekey.asn1        # ASN.1 schema for ECC keys (RFC 5915/5958/5280)
├── include/
│   ├── asn1/                    # ASN.1 + DER layer
│   │   ├── ast.hpp              # Abstract Syntax Tree nodes
│   │   ├── lexer.hpp            # Constexpr tokenizer
│   │   ├── parser.hpp           # Recursive descent parser
│   │   ├── pem.hpp              # PEM encode/decode
│   │   ├── based.hpp            # Base16/32/64 (RFC 4648)
│   │   ├── fixed_string.hpp     # Fixed-capacity string for constexpr
│   │   ├── fixed_vector.hpp     # Fixed-capacity vector for constexpr
│   │   └── der/
│   │       ├── types.hpp        # DER primitive types
│   │       ├── tag.hpp          # Tag utilities
│   │       ├── reader.hpp       # DER binary decoder
│   │       ├── writer.hpp       # DER binary encoder
│   │       └── codegen.hpp      # C++ type generation from ASN.1
│   └── number/                  # Cryptographic math layer
│       ├── number.hpp           # Fixed-width big integers
│       ├── ecc.hpp              # Elliptic curve field/point arithmetic
│       ├── ecdsa.hpp            # ECDSA signing/verification (RFC 6979)
│       ├── ecdh.hpp             # ECDH key agreement
│       ├── sha2.hpp             # SHA-2 family (FIPS 180-4)
│       ├── hmac.hpp             # HMAC (RFC 2104)
│       ├── hkdf.hpp             # HKDF (RFC 5869)
│       ├── aes.hpp              # AES block cipher (FIPS 197)
│       ├── gcm.hpp              # GCM authenticated encryption (SP 800-38D)
│       ├── hash_concept.hpp     # Hash function concept
│       └── block_cipher_concept.hpp  # Block cipher concept
└── tests/                       # Comprehensive test suite
```

## The ASN.1 Layer

### Fixed Containers (`fixed_string.hpp`, `fixed_vector.hpp`)

Since `std::string` and `std::vector` can't be used in constexpr contexts that need to persist results, the project provides `FixedString<Cap>` and `FixedVector<T, Cap>` — backed by `std::array` with a tracked length. These give standard container ergonomics (push_back, iterators, comparison) while being fully constexpr.

### Lexer (`lexer.hpp`)

A constexpr tokenizer that produces a `FixedVector<Token, 1024>` from raw ASN.1 text. It handles 50+ token kinds: keywords (SEQUENCE, CHOICE, OPTIONAL, DEFAULT, etc.), multi-word keywords (BIT STRING, OCTET STRING, OBJECT IDENTIFIER), operators (`::=`, `..`), comments (`--` style), numbers, identifiers, and quoted strings.

### Parser (`parser.hpp`)

A constexpr recursive descent parser that consumes the token stream and builds an `AstModule`. It handles full ASN.1 module syntax:
- Module headers with tag mode defaults (EXPLICIT/IMPLICIT/AUTOMATIC TAGS)
- Type assignments (`TypeName ::= Type`)
- Value assignments (`name OBJECT IDENTIFIER ::= { ... }`)
- SEQUENCE, CHOICE, and SET with named fields, OPTIONAL, DEFAULT
- SEQUENCE OF, SET OF
- Tagged types with class and mode (context-specific, application, etc.)
- Type references and constraints

### AST (`ast.hpp`)

The parsed ASN.1 module is represented as an `AstModule` containing:
- A flat array of `AstNode` entries, each tagged with an `AstNodeKind` (Integer, Boolean, BitString, Sequence, Choice, Tagged, TypeRef, AnyDefinedBy, etc.)
- Named type assignments (mapping names to node indices)
- Named value assignments (mapping OID names to OID component lists)
- Tag metadata (class, mode, number) on each node
- Field lists for constructed types (name, node index, optional/default flags)

### DER Types (`der/types.hpp`)

C++ representations of ASN.1 primitive types:
- **Integer**: big-endian minimal signed two's-complement byte array, with `to_int64()`/`from_int64()`
- **Boolean**, **Null**: trivial wrappers
- **BitString**: byte vector + unused bits count
- **OctetString**: byte vector
- **ObjectIdentifier**: component vector with `to_string()`/`from_string()` (e.g., `"1.2.840.10045.3.1.7"`)

### DER Reader/Writer (`der/reader.hpp`, `der/writer.hpp`)

**Reader** is a stateful binary parser that reads TLV (Tag-Length-Value) encoded data. It can peek/read headers, check tag matches, and extract content bytes. **Writer** builds DER output with methods for each primitive type and a `write_constructed(tag, callback)` pattern for nested encoding.

### DER Codegen (`der/codegen.hpp`)

This is the core type-mapping engine. Given an `AstModule M` and a node index `I`, the `Resolve<M, I>` template maps ASN.1 types to C++ types:
- Primitives map to `der::Integer`, `der::Boolean`, etc.
- `SEQUENCE` becomes `SequenceType<M, I>` — a tuple of fields with compile-time `get<"fieldname">()` accessors, where OPTIONAL/DEFAULT fields are wrapped in `std::optional`
- `CHOICE` becomes `ChoiceType<M, I>` — a `std::variant` of alternatives with `as<"altname">()` accessors
- `SEQUENCE OF` / `SET OF` become `std::vector<T>`
- `ANY DEFINED BY` becomes raw `AnyValue` (unparsed DER bytes)

Recursive `encode()` and `decode()` function templates handle serialization/deserialization, correctly dealing with tag classes, implicit/explicit tagging modes, and nested structures.

### PEM (`pem.hpp`)

Wraps DER binary in PEM text format (`-----BEGIN/END LABEL-----` with Base64 body). Provides both low-level `encode()`/`decode()` and typed `encode_from<M, I>()`/`decode_to<M, I>()` that combine PEM and DER in one step.

### Base Encoding (`based.hpp`)

Complete RFC 4648 codec supporting Base16, Base32, Base32hex, Base64, and Base64url — all fully constexpr with compile-time lookup table generation.

## The Cryptographic Layer

### Big Integers (`number/number.hpp`)

`number<TDigit, NDigits, NDigitMax>` is a fixed-width unsigned integer stored as an array of digits (e.g., `number<uint32_t, 16>` for 512-bit numbers). Supports full arithmetic (+, -, *, /), comparison, bit operations, modular arithmetic, and byte conversion. No dynamic allocation, fully constexpr.

### Elliptic Curve Arithmetic (`ecc.hpp`)

- **`field_element<TCurve>`**: A number that automatically reduces modulo the curve's prime `p` on every operation. Parameterized on a curve type that provides constants (p, a, b, Gx, Gy, n).
- **`point<TCurve>`**: An affine point on the curve with addition, doubling, scalar multiplication (double-and-add), infinity representation, on-curve validation, and serialization (uncompressed format: `0x04 || x || y`).
- Supported curves: **P-256** (NIST), **P-384** (NIST), and **secp256k1** (Bitcoin).

### ECDSA (`ecdsa.hpp`)

Full ECDSA implementation:
- `ecdsa_sign()`: Sign a message hash with a private key
- `ecdsa_verify()`: Verify a signature against a public key and message hash
- `rfc6979_k()`: Deterministic nonce generation per RFC 6979 (using HMAC)
- Low-S normalization for OpenSSL compatibility
- `ecdsa_signature<TCurve>` holds the (r, s) pair

### ECDH (`ecdh.hpp`)

Full ECDH key agreement:
- `ecdh_keypair_from_private()`: Derive public key as d*G
- `ecdh_validate_public_key()`: SEC 1 v2 validation
- `ecdh_raw_shared_secret()`: Compute shared x-coordinate
- `ecdh_derive()`: Raw shared secret + HKDF for key material derivation

### SHA-2 (`sha2.hpp`)

Complete FIPS 180-4 implementation as a template `sha2_state<FullBits, TruncBits>` supporting SHA-256, SHA-224, SHA-512, SHA-384, SHA-512/224, and SHA-512/256. Streaming interface: `init()` → `update()` → `finalize()`. Constexpr, including the K-constant generation via fractional cube roots.

### HMAC (`hmac.hpp`) and HKDF (`hkdf.hpp`)

Generic implementations templated on any type satisfying the `hash_function` concept (defined in `hash_concept.hpp`). HMAC implements RFC 2104, HKDF implements RFC 5869 (extract + expand).

### AES (`aes.hpp`)

Complete FIPS 197 AES block cipher as a template `aes_state<KeyBits>` supporting AES-128, AES-192, and AES-256. The S-box, inverse S-box, and round constants are computed at compile time from first principles via GF(2^8) arithmetic (multiplicative inverse + affine transform). Interface: `init(key)` → `encrypt_block(plaintext)` / `decrypt_block(ciphertext)`. Convenience aliases `aes128`, `aes192`, `aes256` and one-shot `aes_encrypt<KeyBits>()`/`aes_decrypt<KeyBits>()` functions.

### GCM (`gcm.hpp`)

GCM (Galois/Counter Mode) authenticated encryption per NIST SP 800-38D. Templated on any type satisfying the `block_cipher` concept (defined in `block_cipher_concept.hpp`). Implements GF(2^128) multiplication (schoolbook algorithm with GCM's bit-reflected convention), GHASH, and the full GCM encrypt/decrypt pipeline. `gcm_encrypt<Cipher, N>()` returns ciphertext + 128-bit authentication tag. `gcm_decrypt<Cipher, N>()` returns `std::optional` — `std::nullopt` on tag verification failure. Supports standard 12-byte IVs and arbitrary-length IVs via GHASH-based J0 computation.

## ASN.1 Definition

The `definitions/ecprivatekey.asn1` file contains ASN.1 schemas for ECC private keys following RFC 5915 (ECPrivateKey), RFC 5958 (OneAsymmetricKey/PrivateKeyInfo), and RFC 5280 (AlgorithmIdentifier, SubjectPublicKeyInfo). This is the schema that gets `#embed`-ed into tests and parsed at compile time to generate the C++ types for working with real ECC keys.

## Tests

The test suite is comprehensive:

| Test File | What It Covers |
|-----------|---------------|
| `test_fixed_containers.cpp` | FixedString/FixedVector construction, operations |
| `test_lexer.cpp` | Tokenization correctness (compile-time assertions) |
| `test_parser.cpp` | ASN.1 parsing of SEQUENCE, CHOICE, tagged types, references |
| `test_der_primitives.cpp` | DER encode/decode roundtrips for all primitive types |
| `test_der_codegen.cpp` | Type generation, field access, encode/decode of generated types |
| `test_pem.cpp` | PEM encoding/decoding, line wrapping, labels |
| `test_ecc.cpp` | Generator point validation, point arithmetic on P-256 and secp256k1 |
| `test_ecdsa.cpp` | Signing, verification, RFC 6979, SHA-256/384/512, HMAC, OpenSSL interop |
| `test_ecdh.cpp` | Keypair derivation, validation, shared secret, HKDF integration |
| `test_aes.cpp` | AES-128/192/256 FIPS 197 test vectors, encrypt/decrypt roundtrip, compile-time verification |
| `test_gcm.cpp` | AES-GCM SP 800-38D test vectors (cases 1-4, 13-15), tag verification, compile-time test |
| `ecdsa_tool.cpp` | Standalone ECDSA utility |
| `test_openssl_interop.sh` | Shell script verifying signatures/keys work with OpenSSL CLI |

## Build

Requires CMake 3.30+ and a C++26 compiler (tested with recent Clang).

```bash
cmake -B build -G Ninja
cmake --build build
ctest --test-dir build
```

## Design Philosophy

The library is layered bottom-up: containers → lexer → parser → AST → DER codec → codegen → PEM, and separately: big integers → field elements → curve points → ECDSA/ECDH, with SHA-2 → HMAC → HKDF as the hash stack. Everything is header-only, template-heavy, and constexpr. The goal is educational — demonstrating how ASN.1, DER, and ECC work from first principles in modern C++, with the novel twist that the entire pipeline can run at compile time.
