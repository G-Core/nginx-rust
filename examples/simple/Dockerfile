FROM rust:slim-bookworm

RUN apt update && apt install -y curl build-essential libpcre3 libpcre3-dev zlib1g zlib1g-dev libssl-dev libgd-dev libxml2 libxml2-dev uuid-dev clang
RUN curl http://nginx.org/download/nginx-1.25.2.tar.gz | tar xz
