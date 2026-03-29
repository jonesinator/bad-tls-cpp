# CLAUDE.md

## Build & Test

```bash
cmake -B build -G Ninja
cmake --build build
ctest --test-dir build
```

Run a single test: `ctest --test-dir build -R test_name` (e.g., `test_lexer`, `test_ecdsa`).

Full check (unit tests + OpenSSL interop + TLS integration): `cmake --build build --target check`

Containerized full check (Debian sid): `./container-check.sh` (uses podman; `CONTAINER_CMD=docker ./container-check.sh` for docker).

Compiler must support C++26. The build uses `-Wall -Wextra -pedantic -Werror` — all warnings are errors. The flag `-fconstexpr-ops-limit=1000000000` is set for deep compile-time evaluation. `--embed-dir` points to `definitions/` and `${CMAKE_BINARY_DIR}` for `#embed` support. The CA bundle is downloaded at configure time.

## Architecture

Header-only library. No `.cpp` source files — only headers under `include/` and test files under `tests/`.

Five modules with a strict dependency DAG (`number` ← `asn1`, `crypto` ← `x509`, `tls`):
- **`include/asn1/`** — Pure ASN.1 parsing and DER encoding. Pipeline: lexer → parser → AST → DER codegen → PEM. Supports string types (UTF8String, PrintableString, IA5String, etc.) and time types (UTCTime, GeneralizedTime). No crypto dependency.
- **`include/number/`** — Fixed-width big integer arithmetic (`number<TDigit, NDigits>`). Standalone, no dependencies on other modules.
- **`include/crypto/`** — Cryptographic algorithms built on `number/`. ECC (field elements, curve points, ECDSA, ECDH), hashing (SHA-2, HMAC, HKDF, TLS PRF), symmetric encryption (AES, GCM), RSA-PSS signatures, and random number generation (`random_generator` concept with `system_random` CSPRNG and `xoshiro256ss` constexpr PRNG).
- **`include/x509/`** — X.509 certificate chain verification. Depends on both `asn1/` (parsing) and `crypto/` (signature verification). Provides a modular `certificate_verifier` concept for custom policies. Includes Mozilla's root CA bundle (145 certs) embedded via `#embed` and loaded at runtime with `load_mozilla_roots()`.
- **`include/tls/`** — TLS 1.2 client and server. Transport abstraction (`transport` concept with `tcp_transport` and `tcp_listener`), record framing, handshake message types (including CertificateRequest for mTLS), cipher suite definitions, key schedule (standard and Extended Master Secret per RFC 7627), AES-GCM record protection, transcript hashing, role-aware buffered record I/O, ECDH integration, ECDSA and RSA PKCS#1v1.5 signing for ServerKeyExchange and CertificateVerify, private key loading from PEM (SEC 1, PKCS#1, and PKCS#8 for both EC and RSA keys), and both `tls_client<Transport, RNG>` and `tls_server<Transport, RNG>` handshake state machines with mutual TLS support (EC and RSA client/server certificates). Depends on `crypto/` and `x509/`. Supports four ECDHE+AES-GCM cipher suites (ECDSA and RSA, AES-128/256).

The `number/` headers are also available at `/home/aaron/projects/number` as a separate working directory.

## Key Patterns

### Constexpr where possible

The core modules (asn1, number, crypto) are fully constexpr — ASN.1 schemas are embedded via `#embed` and parsed at compile time. The `FixedString<Cap>` and `FixedVector<T, Cap>` types exist because `std::string`/`std::vector` cannot persist across constexpr boundaries. The TLS and x509 modules use `std::vector` and runtime I/O, so they are not constexpr. When adding new functionality in the core modules, maintain constexpr compatibility.

### Template-driven type mapping

`der/codegen.hpp` maps ASN.1 nodes to C++ types via `Resolve<M, I>` where `M` is a constexpr `AstModule` and `I` is a node index. `SequenceType<M, I>` and `ChoiceType<M, I>` are tuple/variant wrappers with named field access (`get<"name">()`, `as<"name">()`). The `encode<M, I>()` and `decode<M, I>()` functions recurse through the AST to serialize/deserialize.

### Curve parameterization

ECC code is templated on a curve type (e.g., `p256`, `secp256k1`) that provides static constants: `p()`, `a()`, `b()`, `gx()`, `gy()`, `n()`. `field_element<TCurve>` auto-reduces mod p. `point<TCurve>` does affine arithmetic. To add a new curve, define a struct with those static methods.

### DER TLV encoding

Reader/Writer follow Tag-Length-Value structure. Writer uses a `write_constructed(tag, callback)` pattern for nested types. Reader uses `peek_header()`/`read_header()`/`read_content()` for stateful parsing.

### TLS binary framing

`tls/record.hpp` provides `TlsReader`/`TlsWriter<Cap>` for big-endian binary serialization (separate from the ASN.1 DER reader/writer). `TlsWriter` supports `patch_u16()`/`patch_u24()` for backpatching length fields. Handshake messages use a 4-byte header (type + 24-bit length) serialized via these helpers.

## Conventions

- No external dependencies. Only the C++ standard library.
- No dynamic allocation in constexpr paths — use `FixedString`/`FixedVector` with sufficient capacity.
- RFC compliance matters: ECDSA uses RFC 6979 deterministic k (with bits2int truncation per Section 2.3.2 for cross-size hash/curve combinations), HMAC follows RFC 2104, HKDF follows RFC 5869, base encodings follow RFC 4648, Extended Master Secret follows RFC 7627. When modifying crypto code, verify against the relevant RFC.
- Low-S normalization is applied in ECDSA for OpenSSL interop. Do not remove it.
- The TLS server includes the `renegotiation_info` extension (RFC 5746) in ServerHello, and the client includes both `renegotiation_info` and `extended_master_secret` (RFC 7627) in ClientHello. These are required by OpenSSL 3.x.
- Tests use `assert()` and compile-time `static_assert` — not a test framework.
- Educational clarity over performance. Scalar multiplication is simple double-and-add, not windowed NAF.

## Common Tasks

**Adding a new ASN.1 type**: Add the `AstNodeKind` in `ast.hpp`, handle it in `parser.hpp`, add DER encode/decode in `codegen.hpp`, add the tag mapping in `tag.hpp`.

**Adding a new curve**: Define a struct with static `p()`, `a()`, `b()`, `gx()`, `gy()`, `n()` methods returning the appropriate `number<>` type. All ECC/ECDSA/ECDH code will work automatically via templates.

**Adding a new hash**: Implement the `hash_function` concept from `hash_concept.hpp` (provide `block_size`, `digest_size`, `init()`, `update()`, `finalize()`). HMAC and HKDF will work automatically.

**Adding a new block cipher**: Follow the `aes.hpp` pattern — `consteval` table generation in a detail namespace, a `_state<KeyBits>` struct with `init(key)`, `encrypt_block()`, `decrypt_block()`, type aliases, and one-shot convenience functions. Ensure the type satisfies the `block_cipher` concept from `block_cipher_concept.hpp` so it works with GCM automatically.

**Adding a TLS cipher suite**: Add the `CipherSuite` enum value in `tls/types.hpp`, add a case to `get_cipher_suite_params()` and `dispatch_cipher_suite()` in `tls/cipher_suite.hpp`, and add a `cipher_suite_traits<>` specialization mapping to the concrete cipher and hash types.

**Adding mTLS support to a tool**: The client needs `client_config::client_certificate_chain` (DER bytes) and `client_private_key` (`tls_private_key` variant — EC or RSA). Load via `load_private_key()` from `tls/private_key.hpp` (auto-detects key type) and `pem::decode_all()`. For EC keys, also set `client_key_curve`. The server needs `server_config::client_ca` (trust_store pointer) and optionally `require_client_cert`. The server accepts both RSA and ECDSA client certificates. Use `server.client_authenticated()` to check if the client presented a valid certificate.

**Debugging constexpr failures**: Constexpr errors surface as compile errors. Look for `throw` statements in constexpr code — these become compile-time error messages (e.g., `ParseError`, `DecodeError`). The thrown string literal is the diagnostic.

## File Hygiene

When adding, removing, or renaming files, always update `README.md` to reflect the change — both the project structure tree and any relevant section descriptions or test tables.
