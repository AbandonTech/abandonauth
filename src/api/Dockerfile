ARG GO_VERSION=1.27.2
ARG VERSION=development
ARG REVISION=unknown

FROM golang:${GO_VERSION} AS source

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Persistence code is generated from the SQL rather than committed, so it is
# built here instead of copied in, where a stale host copy could ship. The
# OpenAPI document is committed source, compiled in by go:embed from the tree
# copied above.
RUN go tool sqlc generate


FROM source AS compile-deployment

ARG VERSION

# CGO_ENABLED=0 produces a binary with no dynamic dependencies, which is what
# lets the runtime stage hold nothing but the binary and a certificate bundle.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-X main.version=${VERSION}" -o /abandonauth ./cmd


FROM source AS compile-development

ARG VERSION

RUN CGO_ENABLED=0 go build -trimpath -tags=devtools -ldflags="-X main.version=${VERSION}" -o /abandonauth ./cmd


# The pinned Goose CLI with every driver but PostgreSQL excluded, kept a
# separate executable so the service binary links no migration code.
FROM source AS compile-migrations

RUN CGO_ENABLED=0 go build -trimpath \
        -tags='no_clickhouse no_libsql no_mssql no_mysql no_sqlite3 no_vertica no_ydb' \
        -o /goose github.com/pressly/goose/v3/cmd/goose


# The binaries, the migration files, a certificate bundle for the provider APIs,
# and a non-root account. There is no shell, no package manager and no
# interpreter.
FROM gcr.io/distroless/static-debian12:nonroot AS runtime

ARG VERSION
ARG REVISION

LABEL org.opencontainers.image.title="AbandonAuth" \
      org.opencontainers.image.description="Authentic Auth Service... Provides identification of a user from multiple external services." \
      org.opencontainers.image.source="https://github.com/AbandonTech/abandonauth" \
      org.opencontainers.image.licenses="GPL-3.0-only" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

EXPOSE 8000

COPY --from=compile-migrations /goose /usr/local/bin/goose
COPY --from=source /src/migrations /migrations

# Migration runs only when a deployment names Goose as the entrypoint.
ENTRYPOINT ["/usr/local/bin/abandonauth"]
CMD ["serve"]


FROM runtime AS development

COPY --from=compile-development /abandonauth /usr/local/bin/abandonauth


# Last, so that a build naming no target produces the image a deployment runs.
FROM runtime AS deployment

COPY --from=compile-deployment /abandonauth /usr/local/bin/abandonauth
