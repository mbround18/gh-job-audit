# syntax=docker/dockerfile:1
FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock* ./
COPY crates ./crates
COPY migrations ./migrations
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release -p knock-knock && cp target/release/knock-knock /knock-knock

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /knock-knock /usr/local/bin/knock-knock
USER nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/knock-knock"]
CMD ["serve"]
