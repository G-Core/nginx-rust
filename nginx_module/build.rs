/*
 * Copyright 2024 G-Core Innovations SARL
 */

use std::{
    env,
    path::{Path, PathBuf},
};

use bindgen::callbacks::{IntKind, ParseCallbacks};

const INCLUDE_SUBDIRS: &[&str] = &[
    "objs/",
    "src/core/",
    "src/event/",
    "src/event/modules/",
    "src/os/unix/",
    "src/http/",
    "src/http/v2/",
    "src/http/modules/",
];

const NGX_QUIC_INCLUDE_SUBDIRS: &[&str] = &["src/event/quic/", "src/http/v3/"];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=wrapper.h");

    let nginx_root_path = std::fs::canonicalize(search_nginx_root_folder()).unwrap();
    let nginx_root = nginx_root_path.to_str().unwrap();

    let mut clang_args = Vec::new();

    // Detect BoringSSL
    let boring_include_dir = "/build/boringssl/include";
    if Path::new(boring_include_dir).is_dir() {
        clang_args.push(format!("-I/{boring_include_dir}"));
    } else {
        let openssl_include_dir = format!("{nginx_root}/contrib/openssl/.openssl/include");
        if Path::new(&openssl_include_dir).is_dir() {
            clang_args.push(format!("-I/{openssl_include_dir}"));
        }
    }

    clang_args.extend(
        INCLUDE_SUBDIRS
            .iter()
            .chain(NGX_QUIC_INCLUDE_SUBDIRS.iter())
            .map(|subdir| format!("-I{nginx_root}/{subdir}")),
    );

    if let Ok(includes) = env::var("NGINX_HEADERS") {
        clang_args.extend(
            includes
                .split(' ')
                .map(|subdir| format!("-I{nginx_root}/{subdir}")),
        )
    }

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .layout_tests(false)
        .allowlist_type("ngx_.*")
        .allowlist_function("ngx_.*")
        .allowlist_var("NGX_.*|ngx_.*|nginx_.*")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .parse_callbacks(Box::new(NginxVersionCallback))
        .clang_args(clang_args)
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Unable to write bindings.");
}

fn search_nginx_root_folder() -> String {
    fn check_nginx_root(path: &Path) -> bool {
        INCLUDE_SUBDIRS.iter().all(|subdir| {
            [path, Path::new(subdir)]
                .iter()
                .collect::<PathBuf>()
                .is_dir()
        })
    }

    if let Ok(nginx_dir) = std::env::var("NGINX_DIR") {
        if check_nginx_root(Path::new(&nginx_dir)) {
            return nginx_dir;
        }
    }

    let base_locations = [
        "..",
        "../..",
        "../../..",
        "../../../..",
        "../../../../..",
        "../../../../../..",
        ".",
    ];

    // First, try to find the include folders in any of the parent folders of this folder,
    // This is the case when this is a submodule of nginx
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    for base in base_locations {
        let folder = format!("{manifest_dir}/{base}");
        if check_nginx_root(Path::new(&folder)) {
            return folder;
        }
    }

    let target_dir = std::env::var("CARGO_TARGET_DIR");
    if let Ok(target_dir) = target_dir.as_ref() {
        for base in base_locations {
            let folder = format!("{target_dir}/{base}");
            if check_nginx_root(Path::new(&folder)) {
                return folder;
            }
        }
    }

    // If we are not a nginx submodule, try to find the folder side by side
    for base in base_locations {
        let base = format!("{manifest_dir}/{base}");
        for entry in std::fs::read_dir(base)
            .expect("Cannot read directory")
            .flatten()
        {
            if entry.path().is_dir() && check_nginx_root(&entry.path()) {
                return entry.path().to_str().unwrap().to_owned();
            }
        }
    }

    if let Ok(target_dir) = target_dir {
        for base in base_locations {
            let base = format!("{target_dir}/{base}");
            for entry in std::fs::read_dir(base)
                .expect("Cannot read directory")
                .flatten()
            {
                if entry.path().is_dir() && check_nginx_root(&entry.path()) {
                    return entry.path().to_str().unwrap().to_owned();
                }
            }
        }
    }

    panic!("We need to generate the Rust bindings from the Nginx header files but the Nginx folder cannot be found. Please git clone the nginx repo in any of these locations relative to this folder: {base_locations:?}");
}

#[derive(Debug)]
struct NginxVersionCallback;

impl ParseCallbacks for NginxVersionCallback {
    fn int_macro(&self, name: &str, value: i64) -> Option<IntKind> {
        if name == "nginx_version" && value >= 1023000 {
            println!("cargo:rustc-cfg=nginx_version_1023000");
        }
        None
    }
}
