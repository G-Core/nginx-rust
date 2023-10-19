
# Description

This repository contains Rust bindings to Nginx, allowing you to create Nginx modules using the Rust language.

# Goals

 - **Safety** - This repository aims to provide safe abstractions on top of Nginx API. In particular, it aims to provide appropriate lifetimes to abstractions to leverage Rust borrow checker. 
 - **Ease of use** - Abstactions are provided to hide Nginx API complexity. 

# Build

## Prerequisites

* Rust: Install with rustup: https://rustup.rs/
* Nginx repository: This project needs the Nginx headers to generate the required Rust bindings to Nginx. At build time the nginx_module crate looks for the nginx folder starting with this module's folder and going upwards up to 4 levels so you can easily have an nginx folder side by side or use this as a submodule for nginx.

## Building a module

Please look at the `simple` example for more details on how to build this.

