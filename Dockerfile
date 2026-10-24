# Runtime-only image. GoReleaser (dockers_v2, see .goreleaser.yaml) builds it
# from the release binaries: the build context holds <os>/<arch>/cortex-mcp
# for each platform, which TARGETPLATFORM (set by BuildKit and Buildah)
# selects, plus LICENSE and THIRD_PARTY_NOTICES. The binary is static (CGO_ENABLED=0), so the image
# needs no shell or package manager and has nothing else to exploit.
# To build one by hand, see docs/releasing.md ("Building an image without
# GoReleaser"). The base is pinned by digest; Dependabot proposes updates.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99
ARG TARGETPLATFORM
COPY LICENSE /LICENSE
COPY THIRD_PARTY_NOTICES /THIRD_PARTY_NOTICES
COPY $TARGETPLATFORM/cortex-mcp /cortex-mcp
ENTRYPOINT ["/cortex-mcp"]
CMD ["serve", "-config", "/config/config.yaml"]
