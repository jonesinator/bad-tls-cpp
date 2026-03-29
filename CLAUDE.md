# CLAUDE.md

## Build & Test

```bash
cmake -B build -G Ninja
cmake --build build
ctest --test-dir build
```

Run a single test: `ctest --test-dir build -R test_name` (e.g., `test_lexer`, `test_ecdsa`).

Compiler must support C++26. The build uses `-Wall -Wextra -pedantic -Werror` — all warnings are errors. The flag `-fconstexpr-ops-limit=1000000000` is set for deep compile-time evaluation. `--embed-dir` points to `definitions/` for `#embed` support.

## Architecture

Header-only library. No `.cpp` source files — only headers under `include/` and test files under `tests/`.

Two independent module trees sharing no code:
- **`include/asn1/`** — ASN.1 parsing and DER encoding. Pipeline: lexer → parser → AST → DER codegen → PEM. Supports string types (UTF8String, PrintableString, IA5String, etc.) and time types (UTCTime, GeneralizedTime) for X.509 certificate parsing. The `x509/` subdirectory provides certificate chain verification with a modular `certificate_verifier` concept for custom policies.
- **`include/number/`** — Cryptographic math. Pipeline: big integers → field elements → curve points → ECDSA/ECDH, plus SHA-2 → HMAC → HKDF → TLS PRF, plus AES → GCM authenticated encryption, plus RSA-PSS signatures.

The `number/` headers are also available at `/home/aaron/projects/number` as a separate working directory.

## Key Patterns

### Everything is constexpr

All types and functions are constexpr. ASN.1 schemas are embedded via `#embed` and parsed at compile time. The `FixedString<Cap>` and `FixedVector<T, Cap>` types exist because `std::string`/`std::vector` cannot persist across constexpr boundaries. When adding new functionality, maintain constexpr compatibility.

### Template-driven type mapping

`der/codegen.hpp` maps ASN.1 nodes to C++ types via `Resolve<M, I>` where `M` is a constexpr `AstModule` and `I` is a node index. `SequenceType<M, I>` and `ChoiceType<M, I>` are tuple/variant wrappers with named field access (`get<"name">()`, `as<"name">()`). The `encode<M, I>()` and `decode<M, I>()` functions recurse through the AST to serialize/deserialize.

### Curve parameterization

ECC code is templated on a curve type (e.g., `p256`, `secp256k1`) that provides static constants: `p()`, `a()`, `b()`, `gx()`, `gy()`, `n()`. `field_element<TCurve>` auto-reduces mod p. `point<TCurve>` does affine arithmetic. To add a new curve, define a struct with those static methods.

### DER TLV encoding

Reader/Writer follow Tag-Length-Value structure. Writer uses a `write_constructed(tag, callback)` pattern for nested types. Reader uses `peek_header()`/`read_header()`/`read_content()` for stateful parsing.

## Conventions

- No external dependencies. Only the C++ standard library.
- No dynamic allocation in constexpr paths — use `FixedString`/`FixedVector` with sufficient capacity.
- RFC compliance matters: ECDSA uses RFC 6979 deterministic k, HMAC follows RFC 2104, HKDF follows RFC 5869, base encodings follow RFC 4648. When modifying crypto code, verify against the relevant RFC.
- Low-S normalization is applied in ECDSA for OpenSSL interop. Do not remove it.
- Tests use `assert()` and compile-time `static_assert` — not a test framework.
- Educational clarity over performance. Scalar multiplication is simple double-and-add, not windowed NAF.

## Common Tasks

**Adding a new ASN.1 type**: Add the `AstNodeKind` in `ast.hpp`, handle it in `parser.hpp`, add DER encode/decode in `codegen.hpp`, add the tag mapping in `tag.hpp`.

**Adding a new curve**: Define a struct with static `p()`, `a()`, `b()`, `gx()`, `gy()`, `n()` methods returning the appropriate `number<>` type. All ECC/ECDSA/ECDH code will work automatically via templates.

**Adding a new hash**: Implement the `hash_function` concept from `hash_concept.hpp` (provide `block_size`, `digest_size`, `init()`, `update()`, `finalize()`). HMAC and HKDF will work automatically.

**Adding a new block cipher**: Follow the `aes.hpp` pattern — `consteval` table generation in a detail namespace, a `_state<KeyBits>` struct with `init(key)`, `encrypt_block()`, `decrypt_block()`, type aliases, and one-shot convenience functions. Ensure the type satisfies the `block_cipher` concept from `block_cipher_concept.hpp` so it works with GCM automatically.

**Debugging constexpr failures**: Constexpr errors surface as compile errors. Look for `throw` statements in constexpr code — these become compile-time error messages (e.g., `ParseError`, `DecodeError`). The thrown string literal is the diagnostic.
