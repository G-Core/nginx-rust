use bindgen::callbacks::{IntKind, ParseCallbacks};
use std::{
    env,
    path::{Path, PathBuf},
};

const INCLUDE_SUBDIRS: &[&str] = &[
    "objs/",
    "src/core/",
    "src/event/",
    "src/event/modules/",
    "src/os/unix/",
    "src/http/",
    "src/http/v2/",
    "src/http/modules/",
    "gcore/gclibhash/include/",
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

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .layout_tests(false)
        .allowlist_type("ngx_.*")
        .allowlist_function("ngx_.*")
        .allowlist_var("NGX_.*|ngx_.*|nginx_.*")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
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
    fn check_nginx_root(path: &str) -> bool {
        INCLUDE_SUBDIRS
            .iter()
            .all(|subdir| [path, subdir].iter().collect::<PathBuf>().is_dir())
    }

    let base_locations = [
        "..",
        "../..",
        "../../..",
        "../../../..",
        "../../../../..",
        ".",
    ];

    // First, try to find the include folders in any of the parent folders of this folder,
    // This is the case when this is a submodule of nginx-gcdn
    for base in base_locations {
        let folder = base.to_string();
        if check_nginx_root(&folder) {
            return folder;
        }
    }

    // If we are not a nginx-gcdn submodule, try to find the folder side by side
    for base in base_locations {
        let folder = format!("{base}/nginx-gcdn");
        if check_nginx_root(&folder) {
            return folder;
        }
    }

    panic!("We need to generate the Rust bindings from the Nginx header files but the Nginx folder cannot be found. Please git clone the ngxin-gcdn repo in any of these locations relative to this folder: {base_locations:?}");
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
