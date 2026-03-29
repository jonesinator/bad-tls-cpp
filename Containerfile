FROM debian:sid AS base

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

FROM base AS build

WORKDIR /src
COPY . .

RUN cmake -B build -G Ninja
RUN cmake --build build

FROM build AS check

RUN cmake --build build --target check
