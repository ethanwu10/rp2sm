FROM silkeh/clang:12 as build

ARG CMAKE_VERSION=3.20.5
RUN wget -O - https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-linux-x86_64.tar.gz | \
    tar -xz --transform "s|^cmake-${CMAKE_VERSION}-linux-x86_64|/usr/local|"

WORKDIR /build

COPY CMakeLists.txt CMakePresets.json .
COPY rp2sm rp2sm
COPY chall chall

RUN cmake -S . -B build --preset docker && \
    cmake --build build --parallel && \
    cmake --install build --prefix /out --strip

FROM scratch as extractor
COPY --from=build /out .
