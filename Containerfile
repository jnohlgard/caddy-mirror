FROM docker.io/library/caddy:builder AS builder
COPY go.mod go.sum *.go /work/
RUN xcaddy build \
  --with github.com/jnohlgard/caddy-mirror=/work

FROM docker.io/library/caddy:latest
COPY --from=builder /usr/bin/caddy /usr/bin/caddy

VOLUME /srv/mirror
