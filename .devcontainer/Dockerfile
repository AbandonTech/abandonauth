FROM mcr.microsoft.com/devcontainers/base:ubuntu-24.04

# Install golang
# https://go.dev/dl/
ARG GOLANG_VERSION="1.24.1"
ARG GOLANG_CHECKSUM="cb2396bae64183cdccf81a9a6df0aea3bce9511fc21469fb89a0c00470088073"
RUN wget --https-only "https://go.dev/dl/go${GOLANG_VERSION}.linux-amd64.tar.gz" -O /tmp/golang.tar.gz && \
    sha256sum /tmp/golang.tar.gz | grep "${GOLANG_CHECKSUM}" && \
    tar -C /usr/local -xf /tmp/golang.tar.gz && \
    rm /tmp/golang.tar.gz
ENV PATH="${PATH}:/usr/local/go/bin"
ENV GOPATH="/usr/local/go"

# Install golang tooling
RUN go install github.com/pressly/goose/v3/cmd/goose@latest && \
    go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest && \
    go install -v github.com/go-delve/delve/cmd/dlv@latest

# Install node
# https://nodejs.org/en/download/prebuilt-binaries
ARG NODE_VERSION="22.14.0"
ARG NODE_CHECKSUM="69b09dba5c8dcb05c4e4273a4340db1005abeafe3927efda2bc5b249e80437ec"
RUN wget --https-only "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz" -O /tmp/node.tar.xz && \
    sha256sum /tmp/node.tar.xz | grep "${NODE_CHECKSUM}" && \
    tar -C /usr/local -xf /tmp/node.tar.xz --strip-components=1 --exclude="CHANGELOG.md" --exclude="LICENSE" --exclude="README.md" && \
    rm /tmp/node.tar.xz && \
    corepack enable && \
    corepack install --global pnpm@9.8.0
ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0