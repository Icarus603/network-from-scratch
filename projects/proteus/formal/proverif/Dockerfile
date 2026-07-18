# syntax=docker/dockerfile:1.7

FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS build

ARG PROVERIF_VERSION=2.05
ARG PROVERIF_SHA256=4871f53c32ab4a04669a060c4886ba5d9080496963fb980a9a62d2c429ceabc4

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gcc \
        libc6-dev \
        make \
        ocaml-nox \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN curl --fail --location --silent --show-error \
        "https://bblanche.gitlabpages.inria.fr/proverif/proverif${PROVERIF_VERSION}.tar.gz" \
        -o proverif.tar.gz \
    && echo "${PROVERIF_SHA256}  proverif.tar.gz" | sha256sum -c - \
    && tar -xzf proverif.tar.gz \
    && cd "proverif${PROVERIF_VERSION}" \
    && ./build -nointeract

FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

ARG PROVERIF_VERSION=2.05
LABEL org.opencontainers.image.title="Proteus ProVerif verifier"
LABEL org.opencontainers.image.version="${PROVERIF_VERSION}"

COPY --from=build "/src/proverif${PROVERIF_VERSION}/proverif" /usr/local/bin/proverif

ENTRYPOINT ["/usr/local/bin/proverif"]
