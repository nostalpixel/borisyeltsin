# Multi-stage build. The runtime image is one static binary and the compiled UI.
# Build for the host architecture. linux/amd64 and linux/arm64 use this same file.

FROM node:22.15.1-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM golang:1.26.9-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/dist ./internal/httpserver/dist
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/boriseltsyn ./cmd/boriseltsyn

FROM alpine:3.22
RUN apk add --no-cache ca-certificates \
    && adduser -D -u 10001 -H -s /sbin/nologin app
COPY --from=build /out/boriseltsyn /usr/local/bin/boriseltsyn
USER app
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/readyz
ENTRYPOINT ["boriseltsyn"]
