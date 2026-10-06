# syntax=docker/dockerfile:1
# Stages: web (node/pnpm -> dist) | chef planner -> cook (deps) -> build (rust) | distroless runtime.

FROM node:25-bookworm-slim AS web
RUN corepack enable
WORKDIR /web
COPY web/package.json web/pnpm-lock.yaml ./
RUN --mount=type=cache,target=/root/.local/share/pnpm/store pnpm install --frozen-lockfile
COPY web ./
RUN pnpm build

FROM lukemathwalker/cargo-chef:latest-rust-1-bookworm AS chef
WORKDIR /src

FROM chef AS planner
COPY Cargo.toml Cargo.lock* ./
COPY crates ./crates
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /src/recipe.json recipe.json
# Dependencies only: cached until Cargo.toml/lock change.
RUN cargo chef cook --release --recipe-path recipe.json
COPY Cargo.toml Cargo.lock* ./
COPY crates ./crates
COPY migrations ./migrations
RUN cargo build --release --workspace --bins

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /src/target/release/knock-knock /usr/local/bin/knock-knock
COPY --from=web /web/dist /srv/web
ENV WEB_DIR=/srv/web
USER nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/knock-knock"]
CMD ["serve"]
