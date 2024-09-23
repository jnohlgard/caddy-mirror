FROM docker.io/library/caddy:builder AS builder
COPY . /work/
RUN --mount=type=cache,target=/go xcaddy build \
  --with github.com/jnohlgard/caddy-mirror=/work

FROM docker.io/library/caddy:latest
COPY --from=builder /usr/bin/caddy /usr/bin/caddy

ENV MIRROR_UPSTREAM="https://mirror.leaseweb.net"
VOLUME /srv/mirror
