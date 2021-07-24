
/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

extern crate bindgen;
use std::env;
use std::path::Path;

#[cfg(windows)]
fn configure_link_for_platform() {
    println!("cargo:rustc-link-lib={}", "Secur32");
    println!("cargo:rustc-link-lib={}", "Crypt32");
    println!("cargo:rustc-link-lib={}", "Advapi32");
    println!("cargo:rustc-link-lib={}", "BCrypt");
    println!("cargo:rustc-link-lib={}", "Kernel32");
    println!("cargo:rustc-link-lib={}", "Ws2_32");
    println!("cargo:rustc-link-lib={}", "Shlwapi");
}

#[cfg(windows)]
fn configure_cmake_for_platform(_: &mut cmake::Config) {

}

#[cfg(target_vendor = "apple")]
fn configure_link_for_platform() {
    println!("cargo:rustc-link-lib=framework={}", "CoreFoundation");
    println!("cargo:rustc-link-lib=framework={}", "Security");
}

#[cfg(target_vendor = "apple")]
fn configure_cmake_for_platform(cmake_config: &mut cmake::Config) {
    cmake_config.define(
        "CMAKE_OSX_SYSROOT",
        "PATH=/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk",
    );
}

#[cfg(all(unix, not(target_vendor = "apple")))]
fn configure_link_for_platform() {
    println!("cargo:rustc-link-lib={}", "s2n");
    println!("cargo:rustc-link-lib={}", "crypto");
    println!("cargo:rustc-link-lib={}", "rt");
}

#[cfg(all(unix, not(target_vendor = "apple")))]
fn configure_cmake_for_platform(_: &mut cmake::Config) {

}

fn compile_aws_crt_ffi() {
    let profile = env::var("PROFILE").unwrap();
    let out_dir = env::var("OUT_DIR").unwrap();

    let cmake_build_type = match profile.as_str() {
        "debug" => "Debug",
        _ => "RelWithDebInfo",
    };

    let mut cmake_config = cmake::Config::new("..");
    cmake_config
        .profile(cmake_build_type)
        .define("CMAKE_INSTALL_LIBDIR", "lib")
        .define("BUILD_SHARED_LIBS", "OFF");

    configure_cmake_for_platform(&mut cmake_config);
    cmake_config.build();

    println!("cargo:rustc-link-search={}", Path::new(&out_dir).join("lib").to_str().unwrap());
    println!("cargo:rustc-link-lib={}", "aws-crt-ffi");
    println!("cargo:rustc-link-lib={}", "aws-c-auth");
    println!("cargo:rustc-link-lib={}", "aws-c-http");
    println!("cargo:rustc-link-lib={}", "aws-c-cal");
    println!("cargo:rustc-link-lib={}", "aws-c-compression");
    println!("cargo:rustc-link-lib={}", "aws-c-io");
    println!("cargo:rustc-link-lib={}", "aws-c-cal");
    println!("cargo:rustc-link-lib={}", "aws-checksums");
    println!("cargo:rustc-link-lib={}", "aws-c-common");
    configure_link_for_platform();
}

fn generate_bindings() {
    let bindings = bindgen::Builder::default()
        .header("../src/api.h")
        .blocklist_type(".*va_list.*")
        .blocklist_type(".*pthread.*")
        .raw_line("#![allow(dead_code)]")
        .raw_line("#![allow(non_upper_case_globals)]")
        .raw_line("#![allow(non_camel_case_types)]")
        .raw_line("#![allow(non_snake_case)]")
        .raw_line("#![allow(deref_nullptr)]")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .rustfmt_bindings(true)
        .generate()
        .expect("Unable to generate bindings for aws-crt-ffi");

    bindings
        .write_to_file(Path::new("src/lib.rs"))
        .expect("Unable to write generated bindings");
}

fn main() {
    compile_aws_crt_ffi();
    generate_bindings();
}
