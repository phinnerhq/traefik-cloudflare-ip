# traefik-cloudflare-ip

A Traefik middleware that restores the visitor IP of requests proxied by Cloudflare.

Requests whose TCP peer is a Cloudflare address get their `CF-Connecting-IP` as remote address, so apps receive a single `X-Forwarded-For` entry and Traefik's own middlewares see the visitor. Every other request loses its `CF-Connecting-IP`. Cloudflare's ranges are fetched from its API: until that succeeds the middleware does nothing, and failures are logged.

Trust is by IP, so traffic sent through Cloudflare from another account (Workers, Spectrum) can still pick its own `CF-Connecting-IP`. Authenticated Origin Pulls with your own certificate is what ties requests to your zones.

> Created on behalf of phinner by Opus 5.5

## Usage

```yaml
# Static configuration
experimental:
  plugins:
    cloudflareip:
      moduleName: github.com/phinnerhq/traefik-cloudflare-ip
      version: v0.1.0

entryPoints:
  websecure:
    http:
      middlewares:
        - cloudflareip@file
```

```yaml
# Dynamic configuration
http:
  middlewares:
    cloudflareip:
      plugin:
        cloudflareip:
          refreshInterval: 24h # at least 1m
```

Traefik's access log records `ClientHost` before middlewares run, so log the `X-Real-Ip` request header to see the visitor (`accessLog.fields.headers.names.X-Real-Ip: keep`). Don't also trust Cloudflare in `forwardedHeaders.trustedIPs`.

## Commands

```sh
# Test
go test -race ./...

# Test as Traefik runs it, from a GOPATH layout
go install github.com/traefik/yaegi/cmd/yaegi@v0.16.1
GO111MODULE=off yaegi test -v .
```
