FROM golang:1.25-bookworm AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
        clang \
        llvm \
        libbpf-dev \
        linux-libc-dev \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && ln -s "/usr/include/$(uname -m)-linux-gnu/asm" /usr/include/asm

WORKDIR /src
COPY go.mod go.sum ./
RUN set -eu; ok=0; \
    for i in 1 2 3 4 5 6; do \
      if go mod download; then ok=1; break; fi; \
      echo "go mod download failed (attempt $i)"; sleep 4; \
    done; \
    test "$ok" = 1
COPY . .
RUN set -eu; ok=0; \
    for i in 1 2 3 4 5 6; do \
      if go generate ./internal/probe; then ok=1; break; fi; \
      echo "go generate failed (attempt $i)"; sleep 4; \
    done; \
    test "$ok" = 1
RUN CGO_ENABLED=0 go build -o /out/packet-exporter ./cmd/packet-exporter

FROM gcr.io/distroless/static-debian12
USER 0
COPY --from=build /out/packet-exporter /packet-exporter
COPY config.yaml /config.yaml
ENTRYPOINT ["/packet-exporter"]
CMD ["-config", "/config.yaml"]
