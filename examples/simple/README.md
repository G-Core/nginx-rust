# Description

This example builds a nginx module that blocks all requests made with an user agent starting with a specified substring. In the example `nginx.conf` it's specified `deny_user_agent curl;` which blocks all requests made by user agents starting with the "curl" substring. So if you start nginx on localhost and run:
* `curl localhost` - will return 403 Forbidden
* `curl localhost --user-agent "not curl" `  - will not block the request 

# Building this example

We build this as a static nginx module, building it alongside nginx itself. This example also contains the `config` and `config.make` files required to integrate this with the Nginx build process.

Steps:

* Use the included Dockerfile to easily create a docker image containing the Rust compiler, the nginx prerequisites and the nginx sources
* Run `docker run --rm -it -v[nginx-rust folder]:/nginx-rust [previously created docker image]`
* Inside the container run: `cd nginx-1.25.2 && ./configure --conf-path=/etc/nginx/nginx.conf  --with-pcre  --lock-path=/var/lock/nginx.lock --pid-path=/var/run/nginx.pid --with-http_ssl_module --modules-path=/etc/nginx/modules --with-http_v2_module --add-module=/nginx-rust/examples/simple && make && make install`
* Start nginx with the provided config: `/usr/local/nginx/sbin/nginx -c /nginx-rust/examples/simple/nginx.conf`
  