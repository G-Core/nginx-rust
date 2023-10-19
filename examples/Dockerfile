FROM rust:slim-bookworm

RUN apt update && apt install -y curl build-essential libpcre3 libpcre3-dev zlib1g zlib1g-dev libssl-dev libgd-dev libxml2 libxml2-dev uuid-dev clang
RUN curl http://nginx.org/download/nginx-1.25.2.tar.gz | tar xz
RUN cd nginx-1.25.2 && ./configure --conf-path=/etc/nginx/nginx.conf  --with-pcre  --lock-path=/var/lock/nginx.lock --pid-path=/var/run/nginx.pid --with-http_ssl_module --modules-path=/etc/nginx/modules --with-http_v2_module --add-module=../examples/simple