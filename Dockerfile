FROM rust:1.85-slim AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p asg-cli

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/agentscope /usr/local/bin/agentscope
ENV RUST_LOG=info ASG_PORT=8100
EXPOSE 8100
# NOTE: real eBPF collection requires running this image with --privileged
# (and a kernel with BTF). By default the server starts with the deterministic
# simulated event source so the demo works anywhere.
CMD ["agentscope", "serve", "--port", "8100", "--source", "simulated"]
