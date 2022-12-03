FROM rust:latest

WORKDIR /usr/src/myapp
COPY . .

RUN apt-get update
RUN apt-get install -y protobuf-compiler

RUN cargo build --release --features bootnode-docker
EXPOSE 26000

ENTRYPOINT RUST_LOG=info cargo run --release --features bootnode-docker