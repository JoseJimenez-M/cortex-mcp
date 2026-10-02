# Runtime-only image: the static binary is built outside (CGO_ENABLED=0), so
# the image has no shell, no package manager, and nothing else to exploit.
# Build: CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o cortex-mcp ./cmd/cortex-mcp
FROM gcr.io/distroless/static-debian12:nonroot
COPY cortex-mcp /cortex-mcp
ENTRYPOINT ["/cortex-mcp"]
CMD ["serve", "-config", "/config/config.yaml"]
