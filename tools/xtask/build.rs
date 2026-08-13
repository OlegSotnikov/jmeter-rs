// SPDX-License-Identifier: Apache-2.0
//! Capture the Cargo/Rust compiler paths selected for this xtask build.
//!
//! The runtime workspace audit uses these build-time anchors instead of
//! resolving cargo through an inherited PATH. This script does not execute
//! a process or inspect repository input.

fn main() {
    if let Ok(cargo) = std::env::var("CARGO") {
        println!("cargo:rustc-env=XTASK_BUILD_CARGO={cargo}");
    }
    if let Ok(rustc) = std::env::var("RUSTC") {
        println!("cargo:rustc-env=XTASK_BUILD_RUSTC={rustc}");
    }
}
