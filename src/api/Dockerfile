ARG GO_VERSION=1.27

FROM golang:${GO_VERSION} AS source

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Persistence code and the API schema are generated from the SQL and the
# annotations rather than committed, so they are built here instead of copied
# in, where a stale host copy could ship.
RUN go tool sqlc generate

RUN go tool swag init \
        --v3.1 \
        --generalInfo cmd/abandonauth.go \
        --dir . \
        --output docs \
        --outputTypes go,json \
        --parseDependency=false \
        --quiet


FROM source AS compile-deployment

# CGO_ENABLED=0 produces a binary with no dynamic dependencies, which is what
# lets the runtime stage hold nothing but the binary and a certificate bundle.
RUN CGO_ENABLED=0 go build -trimpath -o /abandonauth ./cmd


FROM source AS compile-development

RUN CGO_ENABLED=0 go build -trimpath -tags=devtools -o /abandonauth ./cmd


# Nothing but the binary, a certificate bundle for the provider APIs, and a
# non-root account. There is no shell, no package manager and no interpreter.
FROM gcr.io/distroless/static-debian12:nonroot AS runtime

LABEL org.opencontainers.image.title="AbandonAuth" \
      org.opencontainers.image.description="Identity provider and OAuth application broker." \
      org.opencontainers.image.source="https://github.com/AbandonTech/abandonauth" \
      org.opencontainers.image.licenses="GPL-3.0" \
      org.opencontainers.image.version="0.0.1"

EXPOSE 8000

# The schema and the commands that operate on it are in the binary, so the
# recovery path is this same image started with `maintenance`.
ENTRYPOINT ["/usr/local/bin/abandonauth"]
CMD ["serve"]


FROM runtime AS development

COPY --from=compile-development /abandonauth /usr/local/bin/abandonauth


# Last, so that a build naming no target produces the image a deployment runs.
FROM runtime AS deployment

COPY --from=compile-deployment /abandonauth /usr/local/bin/abandonauth
