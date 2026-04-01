FROM debian:sid AS base

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        g++ \
        cmake \
        ninja-build \
        openssl \
        ca-certificates \
        curl \
        python3 \
        strace \
        tcpdump && \
    rm -rf /var/lib/apt/lists/*

FROM base AS build

WORKDIR /src
COPY . .

RUN cmake -B build -G Ninja
RUN cmake --build build

FROM build AS check

ENV CAPTURES=/src/build/captures

CMD ctest --test-dir build --output-on-failure && \
    tests/test_openssl_interop.sh && \
    tests/capture_wrapper.sh "$CAPTURES" tests/test_tls_integration.sh build/tls_connect_tool && \
    tests/capture_wrapper.sh "$CAPTURES" tests/test_tls_server.sh build && \
    tests/capture_wrapper.sh "$CAPTURES" tests/test_tls_openssl_server.sh build && \
    tests/capture_wrapper.sh "$CAPTURES" tests/test_dtls_server.sh build
