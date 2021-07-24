
/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

// This file includes the generated code from bindgen which will make the C functions accessible in Rust for testing
// See build.rs for where bindings.rs comes from
#![allow(dead_code)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(deref_nullptr)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
