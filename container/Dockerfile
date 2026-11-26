# dpdpward container image. Built by .github/workflows/container.yml from the
# Sigstore-verified release archives; nothing is compiled here.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

ARG TARGETOS
ARG TARGETARCH
COPY dist/${TARGETOS}_${TARGETARCH}/dpdpward /usr/local/bin/dpdpward

LABEL org.opencontainers.image.title="dpdpward" \
      org.opencontainers.image.description="Map personal data in code for India's DPDP Act: data map, ROPA, Rule 6 safeguards evidence and breach clocks" \
      org.opencontainers.image.source="https://github.com/Breaktroughf1/dpdpward" \
      org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /src
ENTRYPOINT ["/usr/local/bin/dpdpward"]
CMD ["--help"]
