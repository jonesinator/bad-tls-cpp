/**
 * Mozilla root CA certificate store.
 *
 * Embeds the Mozilla CA bundle (via curl.se's cacert.pem) at compile time
 * and provides load_mozilla_roots() to populate a trust_store at runtime.
 *
 * The PEM bundle is downloaded by CMake at configure time and embedded
 * via #embed. Certificate parsing happens at runtime since trust_store
 * uses dynamic allocation.
 */

#pragma once

#include <x509/trust_store.hpp>

namespace asn1::x509 {

namespace detail {
    inline constexpr unsigned char ca_bundle[] = {
        #embed "cacert.pem"
    };
} // namespace detail

inline trust_store load_mozilla_roots() {
    trust_store store;
    auto blocks = pem::decode_all(
        std::string_view{reinterpret_cast<const char*>(detail::ca_bundle), sizeof(detail::ca_bundle)});
    for (auto& block : blocks) {
        if (block.label == "CERTIFICATE")
            store.add(std::move(block.der));
    }
    return store;
}

} // namespace asn1::x509
