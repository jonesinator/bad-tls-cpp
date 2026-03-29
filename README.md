# bad-tls-cpp

A header-only C++26 library implementing ASN.1 parsing, DER encoding/decoding, elliptic curve cryptography (ECC), and TLS 1.2. Everything is constexpr — the entire pipeline from ASN.1 schema parsing through cryptographic operations and TLS record protection can execute at compile time. Designed for educational purposes, prioritizing clarity over performance.

## Project Structure

```
bad-tls-cpp/
├── CMakeLists.txt                    # Build configuration
├── definitions/                      # Directory for ASN.1 schema files
│   ├── ecprivatekey.asn1             # ASN.1 schema for ECC keys (RFC 5915/5958/5280)
│   └── x509.asn1                     # ASN.1 schema for X.509 certificates (RFC 5280)
├── include/                          # Root of library headers
│   ├── asn1/                         # Pure ASN.1 parsing + DER encoding (no crypto dependency)
│   │   ├── ast.hpp                   # Abstract Syntax Tree nodes
│   │   ├── lexer.hpp                 # Constexpr tokenizer
│   │   ├── parser.hpp                # Recursive descent parser
│   │   ├── pem.hpp                   # PEM encode/decode
│   │   ├── based.hpp                 # Base16/32/64 (RFC 4648)
│   │   ├── fixed_string.hpp          # Fixed-capacity string for constexpr
│   │   ├── fixed_vector.hpp          # Fixed-capacity vector for constexpr
│   │   └── der/                      # ASN.1 DER encoding
│   │       ├── types.hpp             # DER primitive types
│   │       ├── tag.hpp               # Tag utilities
│   │       ├── reader.hpp            # DER binary decoder
│   │       ├── writer.hpp            # DER binary encoder
│   │       └── codegen.hpp           # C++ type generation from ASN.1
│   ├── number/                       # Fixed-width big integer arithmetic (standalone)
│   │   └── number.hpp                # number<TDigit, NDigits> with full arithmetic
│   ├── crypto/                       # Cryptographic algorithms (depends on number/)
│   │   ├── ecc.hpp                   # Elliptic curve field/point arithmetic
│   │   ├── ecdsa.hpp                 # ECDSA signing/verification (RFC 6979)
│   │   ├── ecdh.hpp                  # ECDH key agreement
│   │   ├── sha2.hpp                  # SHA-2 family (FIPS 180-4)
│   │   ├── hmac.hpp                  # HMAC (RFC 2104)
│   │   ├── hkdf.hpp                  # HKDF (RFC 5869)
│   │   ├── aes.hpp                   # AES block cipher (FIPS 197)
│   │   ├── gcm.hpp                   # GCM authenticated encryption (SP 800-38D)
│   │   ├── tls_prf.hpp               # TLS 1.2 PRF (RFC 5246)
│   │   ├── rsa.hpp                   # RSA-PSS signing/verification (RFC 8017)
│   │   ├── random.hpp                # Random number generation (concept + impls)
│   │   ├── hash_concept.hpp          # Hash function concept
│   │   └── block_cipher_concept.hpp  # Block cipher concept
│   ├── x509/                         # X.509 certificate verification (depends on asn1/ + crypto/)
│   │   ├── verify.hpp                # Chain verification, key extraction, sig verify
│   │   ├── trust_store.hpp           # Trusted root certificate store
│   │   ├── mozilla_roots.hpp         # Mozilla CA bundle (145 roots, embedded via #embed)
│   │   └── hostname_verifier.hpp     # Hostname verification (RFC 6125/2818)
│   └── tls/                          # TLS 1.2 client (depends on crypto/ + x509/)
│       ├── types.hpp                 # Wire enums, ProtocolVersion, CipherSuite, etc.
│       ├── record.hpp                # TlsReader/TlsWriter, record framing
│       ├── handshake.hpp             # Handshake message structs + serialization
│       ├── cipher_suite.hpp          # Cipher suite parameters and type-level traits
│       ├── key_schedule.hpp          # Master secret, key expansion, verify_data
│       ├── record_protection.hpp     # AES-GCM record encrypt/decrypt (RFC 5288)
│       ├── transcript.hpp            # Handshake transcript hash accumulator
│       ├── transport.hpp             # Transport concept + memory_transport mock
│       ├── connection.hpp            # Record I/O, SKE verification, ECDH helpers
│       ├── client.hpp                # tls_client handshake state machine
│       └── tcp_transport.hpp         # POSIX TCP socket transport
└── tests/                            # Comprehensive test suite
```

The five modules form a strict dependency DAG:

```
number (standalone)
  ↑        ↑
  │        │
asn1    crypto
  ↑        ↑
  └──x509──┘
           ↑
          tls
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

## Big Integers (`number/number.hpp`)

`number<TDigit, NDigits, NDigitMax>` is a fixed-width unsigned integer stored as an array of digits (e.g., `number<uint32_t, 16>` for 512-bit numbers). Supports full arithmetic (+, -, *, /), comparison, bit operations, modular arithmetic, and byte conversion. No dynamic allocation, fully constexpr.

## The Cryptographic Layer (`crypto/`)

### Elliptic Curve Arithmetic (`crypto/ecc.hpp`)

- **`field_element<TCurve>`**: A number that automatically reduces modulo the curve's prime `p` on every operation. Parameterized on a curve type that provides constants (p, a, b, Gx, Gy, n).
- **`point<TCurve>`**: An affine point on the curve with addition, doubling, scalar multiplication (double-and-add), infinity representation, on-curve validation, and serialization (uncompressed format: `0x04 || x || y`).
- Supported curves: **P-256** (NIST), **P-384** (NIST), and **secp256k1** (Bitcoin).

### ECDSA (`crypto/ecdsa.hpp`)

Full ECDSA implementation:
- `ecdsa_sign()`: Sign a message hash with a private key
- `ecdsa_verify()`: Verify a signature against a public key and message hash
- `rfc6979_k()`: Deterministic nonce generation per RFC 6979 (using HMAC)
- Low-S normalization for OpenSSL compatibility
- `ecdsa_signature<TCurve>` holds the (r, s) pair

### ECDH (`crypto/ecdh.hpp`)

Full ECDH key agreement:
- `ecdh_keypair_from_private()`: Derive public key as d*G
- `ecdh_validate_public_key()`: SEC 1 v2 validation
- `ecdh_raw_shared_secret()`: Compute shared x-coordinate
- `ecdh_derive()`: Raw shared secret + HKDF for key material derivation

### SHA-2 (`crypto/sha2.hpp`)

Complete FIPS 180-4 implementation as a template `sha2_state<FullBits, TruncBits>` supporting SHA-256, SHA-224, SHA-512, SHA-384, SHA-512/224, and SHA-512/256. Streaming interface: `init()` → `update()` → `finalize()`. Constexpr, including the K-constant generation via fractional cube roots.

### HMAC (`crypto/hmac.hpp`) and HKDF (`crypto/hkdf.hpp`)

Generic implementations templated on any type satisfying the `hash_function` concept (defined in `crypto/hash_concept.hpp`). HMAC implements RFC 2104, HKDF implements RFC 5869 (extract + expand).

### AES (`crypto/aes.hpp`)

Complete FIPS 197 AES block cipher as a template `aes_state<KeyBits>` supporting AES-128, AES-192, and AES-256. The S-box, inverse S-box, and round constants are computed at compile time from first principles via GF(2^8) arithmetic (multiplicative inverse + affine transform). Interface: `init(key)` → `encrypt_block(plaintext)` / `decrypt_block(ciphertext)`. Convenience aliases `aes128`, `aes192`, `aes256` and one-shot `aes_encrypt<KeyBits>()`/`aes_decrypt<KeyBits>()` functions.

### TLS 1.2 PRF (`crypto/tls_prf.hpp`)

TLS 1.2 pseudorandom function per RFC 5246 Section 5. `p_hash<THash, L>()` iterates HMAC to produce `L` bytes of output via the A(i) chain. `tls_prf<THash, L>()` prepends the label to the seed and calls `p_hash`. Templated on any `hash_function` — SHA-256 for the default TLS 1.2 cipher suites, SHA-384 for AES-256 suites.

### RSA-PSS (`crypto/rsa.hpp`)

RSA signature signing and verification per RFC 8017. Supports both **RSA-PSS** (RSASSA-PSS, Sections 8.1/9.1) and **PKCS#1 v1.5** (RSASSA-PKCS1-v1_5, Sections 8.2/9.2). PSS uses MGF1 mask generation with caller-supplied salt. PKCS#1 v1.5 uses hardcoded DigestInfo DER prefixes for SHA-256/384/512 per Section 9.2 Note 1. Templated on `TNum` (big integer type, must be double the modulus width for intermediate product safety) and `THash` (any `hash_function`). Standard configurations: RSA-2048/SHA-256 with `number<uint32_t, 128>`, RSA-4096/SHA-384 with `number<uint32_t, 256>`.

### GCM (`crypto/gcm.hpp`)

GCM (Galois/Counter Mode) authenticated encryption per NIST SP 800-38D. Templated on any type satisfying the `block_cipher` concept (defined in `crypto/block_cipher_concept.hpp`). Implements GF(2^128) multiplication (schoolbook algorithm with GCM's bit-reflected convention), GHASH, and the full GCM encrypt/decrypt pipeline. `gcm_encrypt<Cipher, N>()` returns ciphertext + 128-bit authentication tag. `gcm_decrypt<Cipher, N>()` returns `std::optional` — `std::nullopt` on tag verification failure. Supports standard 12-byte IVs and arbitrary-length IVs via GHASH-based J0 computation. Runtime-length variants `gcm_encrypt_rt`/`gcm_decrypt_rt` accept `std::span` for variable-length payloads (used by TLS record protection).

### Random Number Generation (`crypto/random.hpp`)

Defines a `random_generator` concept requiring a single `fill(std::span<uint8_t>)` method. Two implementations:
- **`system_random`**: CSPRNG backed by `std::random_device`. Runtime only.
- **`xoshiro256ss`**: Deterministic PRNG (Blackman & Vigna, 2018) seeded from a `uint64_t`. Fully constexpr — suitable for compile-time testing but **not** cryptographically secure.

Helper functions: `random_bytes<N>(rng)` fills an `std::array`, `random_scalar<TCurve>(rng)` generates a value in [1, n-1] via rejection sampling for ECC key generation.

### Mozilla Root CA Bundle (`x509/mozilla_roots.hpp`)

Embeds Mozilla's trusted root CA certificates (from curl.se's `cacert.pem`) via `#embed`. The PEM bundle is downloaded by CMake at configure time with SHA-256 verification. `load_mozilla_roots()` parses all 145 certificates at runtime and returns a populated `trust_store`. The multi-PEM parsing uses `pem::decode_all()` which iterates through all `BEGIN`/`END` blocks in a single file.

### Hostname Verification (`x509/hostname_verifier.hpp`)

A `certificate_verifier` that checks the server's certificate against an expected hostname per RFC 6125 / RFC 2818. Checks Subject Alternative Name (SAN) dNSName entries first; falls back to Common Name (CN) only if no SAN extension exists. Supports wildcard matching (`*.example.com` matches `foo.example.com` but not `foo.bar.example.com` or `example.com`). Only verifies the leaf certificate (depth == 0).

## The TLS 1.2 Layer (`tls/`)

The TLS module implements a TLS 1.2 client (RFC 5246): types, binary serialization, key derivation, record-level encryption, transport abstraction, buffered record I/O, ECDHE key exchange, ServerKeyExchange signature verification, and a complete handshake state machine with application data send/receive. It uses its own big-endian binary framing, not ASN.1 DER.

### Wire Types (`tls/types.hpp`)

Enumerations and value types matching the TLS binary protocol: `ContentType`, `HandshakeType`, `CipherSuite`, `ProtocolVersion`, `AlertLevel`/`AlertDescription`, `NamedCurve` (P-256, P-384), `SignatureAndHashAlgorithm`, `Random`, `SessionId`, and `CompressionMethod`. All are `enum class` with explicit underlying types matching their wire widths.

### Record Layer (`tls/record.hpp`)

`TlsReader` and `TlsWriter<Cap>` provide big-endian binary serialization analogous to the DER reader/writer. `TlsRecord` represents a framed record (type + version + fragment). `write_record()`/`read_record()` handle serialization. `TlsWriter` supports `patch_u16()`/`patch_u24()` for backpatching length fields after the body is written.

### Handshake Messages (`tls/handshake.hpp`)

Structs and serialization for all handshake message types: `ClientHello`, `ServerHello`, `CertificateMessage`, `ServerKeyExchangeEcdhe`, `ServerHelloDone`, `ClientKeyExchangeEcdhe`, `CertificateVerify`, and `Finished`. Client-sent messages have `write_*` functions; server-sent messages have `read_*` functions. Extension helpers build the mandatory ClientHello extensions (supported_groups, ec_point_formats, signature_algorithms).

### Cipher Suite Definitions (`tls/cipher_suite.hpp`)

Maps the four supported cipher suites to algorithm parameters and C++ types. `CipherSuiteParams` provides runtime-queryable sizes. `cipher_suite_traits<Suite>` provides compile-time type mappings. `dispatch_cipher_suite()` bridges runtime selection to compile-time dispatch.

Supported suites:
- `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` (0xC02F)
- `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` (0xC030)
- `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` (0xC02B)
- `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` (0xC02C)

### Key Schedule (`tls/key_schedule.hpp`)

Master secret derivation, key block expansion, and Finished verify_data computation using the existing TLS PRF from `crypto/tls_prf.hpp`. `derive_master_secret()` implements RFC 5246 Section 8.1. `derive_key_block()` implements Section 6.3 (note: seed order is reversed vs. master secret derivation). `compute_verify_data()` implements Section 7.4.9.

### Record Protection (`tls/record_protection.hpp`)

AES-GCM record encryption and decryption per RFC 5288. `build_nonce()` constructs the 12-byte GCM nonce from a 4-byte fixed IV and 8-byte sequence number. `build_additional_data()` constructs the 13-byte AAD. `encrypt_record()` produces `explicit_nonce || ciphertext || tag`. `decrypt_record()` returns `std::optional` — `std::nullopt` on authentication failure.

### Transcript Hash (`tls/transcript.hpp`)

A thin wrapper around any `hash_function` for accumulating handshake messages. `TranscriptHash<THash>` supports `update()`, non-destructive `current_hash()` (finalizes a copy), and `finalize()`.

### Transport (`tls/transport.hpp`)

Defines the `transport` concept for byte-level I/O (`read(span)` → `size_t`, `write(span)` → `size_t`). Provides `memory_transport` — a constexpr-capable mock with pre-loaded rx/tx buffers for testing.

### Connection Infrastructure (`tls/connection.hpp`)

`tls_error` enum and `tls_result<T>` for error propagation. `record_io<Transport>` provides buffered record-layer I/O over any transport, with encryption state management and runtime cipher suite dispatch via `dispatch_cipher_suite`. `handshake_reader` handles message framing within handshake records (coalescing and fragmentation). `verify_server_key_exchange()` verifies the ServerKeyExchange signature (ECDSA or RSA) against the server's certificate public key. `compute_ecdh_exchange()` performs the full ECDHE key exchange: parse server point, validate, generate ephemeral keypair, compute shared secret, serialize client public key.

### TLS Client (`tls/client.hpp`)

`tls_client<Transport, RNG>` performs a full TLS 1.2 ECDHE handshake and provides encrypted application data send/receive. `client_config` specifies cipher suites, curves, signature algorithms, an optional `trust_store` for certificate chain verification, and an optional `hostname` for SAN/CN verification. The handshake uses a two-phase design: Phase 1 (ClientHello/ServerHello) runs before the cipher suite is known, buffering transcript bytes. Phase 2 dispatches via `dispatch_cipher_suite` into a fully-templated continuation where the hash and cipher types are compile-time. Methods: `handshake()`, `send()`, `recv()`, `close()`.

### TCP Transport (`tls/tcp_transport.hpp`)

POSIX socket implementation of the `transport` concept. Constructor takes `(hostname, port)` and connects via `getaddrinfo` (IPv4/IPv6). Blocking I/O, RAII (destructor closes), move-only. `write()` loops internally to ensure all bytes are sent. `read()` returns a single `::read()` result (partial reads handled by `record_io`).

## ASN.1 Definitions

The `definitions/` directory contains ASN.1 schemas that get `#embed`-ed and parsed at compile time:

- **`ecprivatekey.asn1`** — ECC key structures per RFC 5915 (ECPrivateKey), RFC 5958 (OneAsymmetricKey/PrivateKeyInfo), and RFC 5280 (AlgorithmIdentifier, SubjectPublicKeyInfo, ECDSA-Sig-Value).
- **`x509.asn1`** — X.509 certificate structures per RFC 5280 (Certificate, TBSCertificate, Name, Validity, Extensions). Uses `IMPLICIT TAGS` as the default tagging mode.

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
| `test_random.cpp` | Concept satisfaction, xoshiro determinism, system_random output, random_scalar bounds |
| `test_tls_prf.cpp` | TLS 1.2 PRF with SHA-256 and SHA-384, compile-time verification |
| `test_rsa.cpp` | RSA-PSS and PKCS#1 v1.5 sign/verify, known-signature verification, negative tests |
| `test_x509.cpp` | X.509 certificate parsing, field extraction, RDN access, extension parsing |
| `test_x509_verify.cpp` | Certificate chain verification, TBS extraction, key extraction, trust store |
| `test_tls_types.cpp` | TLS wire enum values, ProtocolVersion, SessionId, SignatureAndHashAlgorithm |
| `test_tls_record.cpp` | TlsReader/TlsWriter roundtrips, record framing, incomplete records, sub-readers |
| `test_tls_handshake.cpp` | ClientHello serialization, ServerHello/Certificate/SKE parsing, Finished roundtrip |
| `test_tls_key_schedule.cpp` | Master secret derivation, key block expansion, verify_data, transcript hash |
| `test_tls_record_protection.cpp` | Nonce/AAD construction, AES-128/256-GCM encrypt/decrypt, tamper detection, runtime GCM |
| `test_tls_client.cpp` | Full ECDHE handshake with memory_transport, certificate/SKE verification, key derivation, encrypted Finished exchange |
| `test_mozilla_roots.cpp` | Mozilla CA bundle loading (145 roots), subject DER extraction |
| `test_hostname_verifier.cpp` | Exact/wildcard hostname matching, SAN extraction, CN fallback, verifier integration |
| `test_tcp_transport.cpp` | Transport concept satisfaction, connection failure handling, move semantics |
| `ecdsa_tool.cpp` | Standalone ECDSA/ECDH utility |
| `tls_connect_tool.cpp` | End-to-end TLS client: connects to a server, handshakes, sends HTTP GET |
| `test_tls_integration.sh` | Integration test: connects to 10 public sites, rejects 2 bad-cert sites |
| `rsa_tool.cpp` | Standalone RSA-PSS sign/verify utility |
| `x509_tool.cpp` | Standalone X.509 chain verification utility |
| `test_openssl_interop.sh` | Shell script verifying ECDSA, ECDH, RSA-PSS, and X.509 work with OpenSSL CLI |

## Build

Requires CMake 3.30+, a C++26 compiler (tested with GCC 15 on Debian sid), and internet access for the first configure (downloads Mozilla's CA bundle) and for TLS integration tests. The CA bundle is cached in the build directory and verified by SHA-256 hash.

```bash
cmake -B build -G Ninja    # downloads cacert.pem on first run
cmake --build build
ctest --test-dir build      # unit tests only
cmake --build build --target check  # full: unit + OpenSSL interop + TLS integration
```

### Containerized Build

A `Containerfile` (Debian sid) provides a reproducible build environment with all dependencies. No local toolchain required.

```bash
./container-check.sh                        # uses podman
CONTAINER_CMD=docker ./container-check.sh   # uses docker
```

This builds from scratch inside the container and runs the full `check` target (25 unit tests, 99 OpenSSL interop tests, 16 TLS integration tests).

## Design Philosophy

The library is organized into five modules with clean dependency boundaries: `asn1/` (pure parsing, no crypto), `number/` (standalone big integers), `crypto/` (cryptographic algorithms built on `number/`), `x509/` (certificate verification combining `asn1/` and `crypto/`), and `tls/` (TLS 1.2 data layer built on `crypto/`). Within each module, the code is layered bottom-up: containers → lexer → parser → AST → DER codec → codegen → PEM, and separately: big integers → field elements → curve points → ECDSA/ECDH, with SHA-2 → HMAC → HKDF as the hash stack. Everything is header-only, template-heavy, and constexpr. The goal is educational — demonstrating how ASN.1, DER, ECC, and TLS work from first principles in modern C++, with the novel twist that the entire pipeline can run at compile time.
