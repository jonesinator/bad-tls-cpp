cmake_minimum_required(VERSION 3.30)
project(asn1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_library(asn1 INTERFACE)
target_include_directories(asn1 INTERFACE include)

# Download Mozilla CA bundle (pinned version with SHA-256 verification)
set(CACERT_URL "https://curl.se/ca/cacert-2026-03-19.pem")
set(CACERT_FILE "${CMAKE_BINARY_DIR}/cacert.pem")
set(CACERT_SHA256 "b6e66569cc3d438dd5abe514d0df50005d570bfc96c14dca8f768d020cb96171")

if(NOT EXISTS "${CACERT_FILE}")
    message(STATUS "Downloading Mozilla CA bundle...")
    file(DOWNLOAD "${CACERT_URL}" "${CACERT_FILE}"
         EXPECTED_HASH SHA256=${CACERT_SHA256}
         TLS_VERIFY ON)
endif()

enable_testing()

function(add_asn1_test name)
    add_executable(${name} tests/${name}.cpp)
    target_link_libraries(${name} PRIVATE asn1)
    target_include_directories(${name} PRIVATE ${CMAKE_SOURCE_DIR})
    target_compile_options(${name} PRIVATE -Wall -Wextra -pedantic -Werror --embed-dir=${CMAKE_SOURCE_DIR} --embed-dir=${CMAKE_BINARY_DIR} -fconstexpr-ops-limit=1000000000)
    add_test(NAME ${name} COMMAND ${name})
endfunction()

add_asn1_test(test_fixed_containers)
add_asn1_test(test_lexer)
add_asn1_test(test_parser)
add_asn1_test(test_der_primitives)
add_asn1_test(test_der_codegen)
add_asn1_test(test_pem)
add_asn1_test(test_number)
add_asn1_test(test_sha2)
add_asn1_test(test_ecc)
add_asn1_test(test_ecdsa)
add_asn1_test(test_ecdh)
add_asn1_test(test_x25519)
add_asn1_test(test_chacha20)
add_asn1_test(test_poly1305)
add_asn1_test(test_chacha20_poly1305)
add_asn1_test(test_aes)
add_asn1_test(test_gcm)
add_asn1_test(test_tls_prf)
add_asn1_test(test_random)
add_asn1_test(test_rsa)
add_asn1_test(test_x509)
add_asn1_test(test_x509_verify)
add_asn1_test(test_tls_types)
add_asn1_test(test_tls_record)
add_asn1_test(test_tls_handshake)
add_asn1_test(test_tls_key_schedule)
add_asn1_test(test_tls13_key_schedule)
add_asn1_test(test_tls_record_protection)
add_asn1_test(test_tls13_record_protection)
add_asn1_test(test_tls13_extensions)
add_asn1_test(test_tls13_handshake)
add_asn1_test(test_tls13_connection)
add_asn1_test(test_tls_client)
add_asn1_test(test_mozilla_roots)
add_asn1_test(test_hostname_verifier)
add_asn1_test(test_tcp_transport)
add_asn1_test(test_private_key)
add_asn1_test(test_dtls_record)
add_asn1_test(test_dtls_record_protection)
add_asn1_test(test_dtls_handshake)

add_executable(x509_tool tests/x509_tool.cpp)
target_link_libraries(x509_tool PRIVATE asn1)
target_include_directories(x509_tool PRIVATE ${CMAKE_SOURCE_DIR})
target_compile_options(x509_tool PRIVATE -Wall -Wextra -pedantic -Werror --embed-dir=${CMAKE_SOURCE_DIR} --embed-dir=${CMAKE_BINARY_DIR} -fconstexpr-ops-limit=1000000000)

add_executable(rsa_tool tests/rsa_tool.cpp)
target_link_libraries(rsa_tool PRIVATE asn1)
target_include_directories(rsa_tool PRIVATE ${CMAKE_SOURCE_DIR})
target_compile_options(rsa_tool PRIVATE -Wall -Wextra -pedantic -Werror --embed-dir=${CMAKE_SOURCE_DIR} --embed-dir=${CMAKE_BINARY_DIR} -fconstexpr-ops-limit=1000000000)

add_executable(ecdsa_tool tests/ecdsa_tool.cpp)
target_link_libraries(ecdsa_tool PRIVATE asn1)
target_include_directories(ecdsa_tool PRIVATE ${CMAKE_SOURCE_DIR})
target_compile_options(ecdsa_tool PRIVATE -Wall -Wextra -pedantic -Werror --embed-dir=${CMAKE_SOURCE_DIR} --embed-dir=${CMAKE_BINARY_DIR} -fconstexpr-ops-limit=1000000000)

add_executable(tls_connect_tool tests/tls_connect_tool.cpp)
target_link_libraries(tls_connect_tool PRIVATE asn1)
target_include_directories(tls_connect_tool PRIVATE ${CMAKE_SOURCE_DIR})
target_compile_options(tls_connect_tool PRIVATE -Wall -Wextra -pedantic -Werror -O2 --embed-dir=${CMAKE_SOURCE_DIR} --embed-dir=${CMAKE_BINARY_DIR} -fconstexpr-ops-limit=1000000000)

add_executable(tls_server_tool tests/tls_server_tool.cpp)
target_link_libraries(tls_server_tool PRIVATE asn1)
target_include_directories(tls_server_tool PRIVATE ${CMAKE_SOURCE_DIR})
target_compile_options(tls_server_tool PRIVATE -Wall -Wextra -pedantic -Werror -O2 --embed-dir=${CMAKE_SOURCE_DIR} --embed-dir=${CMAKE_BINARY_DIR} -fconstexpr-ops-limit=1000000000)

add_executable(dtls_connect_tool tests/dtls_connect_tool.cpp)
target_link_libraries(dtls_connect_tool PRIVATE asn1)
target_include_directories(dtls_connect_tool PRIVATE ${CMAKE_SOURCE_DIR})
target_compile_options(dtls_connect_tool PRIVATE -Wall -Wextra -pedantic -Werror -O2 --embed-dir=${CMAKE_SOURCE_DIR} --embed-dir=${CMAKE_BINARY_DIR} -fconstexpr-ops-limit=1000000000)

add_executable(dtls_server_tool tests/dtls_server_tool.cpp)
target_link_libraries(dtls_server_tool PRIVATE asn1)
target_include_directories(dtls_server_tool PRIVATE ${CMAKE_SOURCE_DIR})
target_compile_options(dtls_server_tool PRIVATE -Wall -Wextra -pedantic -Werror -O2 --embed-dir=${CMAKE_SOURCE_DIR} --embed-dir=${CMAKE_BINARY_DIR} -fconstexpr-ops-limit=1000000000)


# Full check: build everything, run unit tests, OpenSSL interop, TLS integration
add_custom_target(check
    COMMAND ${CMAKE_CTEST_COMMAND} --test-dir ${CMAKE_BINARY_DIR} --output-on-failure
    COMMAND ${CMAKE_SOURCE_DIR}/tests/test_openssl_interop.sh
    COMMAND ${CMAKE_SOURCE_DIR}/tests/test_tls_integration.sh ${CMAKE_BINARY_DIR}/tls_connect_tool
    COMMAND ${CMAKE_SOURCE_DIR}/tests/test_tls_server.sh ${CMAKE_BINARY_DIR}
    COMMAND ${CMAKE_SOURCE_DIR}/tests/test_tls_openssl_server.sh ${CMAKE_BINARY_DIR}
    COMMAND ${CMAKE_SOURCE_DIR}/tests/test_dtls_server.sh ${CMAKE_BINARY_DIR}
    DEPENDS ${CMAKE_SOURCE_DIR}/tests/test_openssl_interop.sh
            ${CMAKE_SOURCE_DIR}/tests/test_tls_integration.sh
            ${CMAKE_SOURCE_DIR}/tests/test_tls_server.sh
            ${CMAKE_SOURCE_DIR}/tests/test_tls_openssl_server.sh
            ${CMAKE_SOURCE_DIR}/tests/test_dtls_server.sh
            tls_connect_tool tls_server_tool x509_tool rsa_tool ecdsa_tool
            dtls_connect_tool dtls_server_tool
    COMMENT "Running full check: unit tests + OpenSSL interop + TLS integration + server + DTLS"
    USES_TERMINAL
)
