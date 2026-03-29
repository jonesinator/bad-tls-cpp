FROM debian:sid

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        g++ \
        cmake \
        ninja-build \
        openssl \
        ca-certificates \
        curl \
        python3 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

RUN cmake -B build -G Ninja -DSTATIC_TOOLS=ON
RUN cmake --build build
RUN cmake --build build --target check
