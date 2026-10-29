# Build stage
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /ztproxy ./cmd/ztproxy

# Minimal runtime: no shell, runs as non-root
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /ztproxy /ztproxy
COPY configs /configs
EXPOSE 8080 9090
USER nonroot:nonroot
ENTRYPOINT ["/ztproxy", "-listen", ":8080", "-admin", ":9090", "-policy", "/configs/policy.json", "-users", "/configs/users.json"]
