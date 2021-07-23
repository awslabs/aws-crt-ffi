
/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
use aws_crt_c_flags::{CRTModuleBuildInfo, HeaderType};
use std::path::Path;

#[cfg(windows)]
fn add_system_deps_to_link_line() {
    println!("cargo:rustc-link-lib={}", "Secur32");
    println!("cargo:rustc-link-lib={}", "Crypt32");
    println!("cargo:rustc-link-lib={}", "Advapi32");
    println!("cargo:rustc-link-lib={}", "BCrypt");
    println!("cargo:rustc-link-lib={}", "Kernel32");
    println!("cargo:rustc-link-lib={}", "Ws2_32");
    println!("cargo:rustc-link-lib={}", "Shlwapi");
}

#[cfg(windows)]
fn add_system_cmake_customizations(_: &mut cmake::Config) {

}

#[cfg(target_vendor = "apple")]
fn add_system_deps_to_link_line() {
    println!("cargo:rustc-link-lib=framework={}", "CoreFoundation");
    println!("cargo:rustc-link-lib=framework={}", "Security");
}

#[cfg(target_vendor = "apple")]
fn add_system_cmake_customizations(cmake_config: &mut cmake::Config) {
    cmake_config.define(
        "CMAKE_OSX_SYSROOT",
        "PATH=/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk",
    );
}

#[cfg(all(unix, not(target_vendor = "apple")))]
fn add_system_deps_to_link_line() {
    println!("cargo:rustc-link-lib={}", "s2n");
    println!("cargo:rustc-link-lib={}", "crypto");
    println!("cargo:rustc-link-lib={}", "rt");
}

#[cfg(all(unix, not(target_vendor = "apple")))]
fn add_system_cmake_customizations(_: &mut cmake::Config) {

}

fn main() {
    let profile = std::env::var("PROFILE").unwrap();
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let cmake_build_type = match profile.as_str() {
        "debug" => "Debug",
        _ => "RelWithDebInfo",
    };

    let cmake_binaries = Path::new(out_dir.as_str()).join(Path::new("cmake"));
    //let cmake_install = Path::new(out_dir.as_str()).join(Path::new("cmake/install"));

    let mut cmake_config = cmake::Config::new("..");
    cmake_config
        .profile(cmake_build_type)
        .define("CMAKE_INSTALL_LIBDIR", "lib")
        .define("BUILD_SHARED_LIBS", "OFF");

    add_system_cmake_customizations(&mut cmake_config);
    cmake_config.build();

    // let mut build_info = CRTModuleBuildInfo::new("aws-checksums");
    // build_info.module_links_dependency("aws-crt-ffi");
    //
    // // Add source to include dirs, and then add all source files
    // let source_dir = Path::new("../src");
    // build_info.include_dir(source_dir, HeaderType::Private);
    // for entry in source_dir.read_dir().expect("No source files found in ../src") {
    //     if let Ok(entry) = entry {
    //         build_info.file(entry.path().as_path());
    //     }
    // }
    //
    // build_info.build();

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
    add_system_deps_to_link_line();
}
