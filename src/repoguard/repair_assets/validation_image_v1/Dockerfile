FROM docker.io/library/python:3.12.13-bookworm@sha256:058149828b8d4a90425f5ae6d255ee1fcfe73bf7d749635d824f4e033460d83c AS upstream

FROM scratch
COPY --from=upstream / /
ENV PATH=/usr/local/bin:/usr/bin:/bin
LABEL com.repoguard.validation-image.schema="1" \
    com.repoguard.validation-image.base.config="sha256:3a8bac27170e870e5499f2c0ea9d997a3a0d78a6b2c84dd5ddca56895a29bee4" \
    com.repoguard.validation-image.upstream.revision="3362634339580d3232e65a66dd5a36c47ae7ff14" \
    org.opencontainers.image.base.digest="sha256:058149828b8d4a90425f5ae6d255ee1fcfe73bf7d749635d824f4e033460d83c" \
    org.opencontainers.image.base.name="docker.io/library/python:3.12.13-bookworm" \
    org.opencontainers.image.title="RepoGuard repair validation" \
    org.opencontainers.image.version="python3.12.13-bookworm-v1"
