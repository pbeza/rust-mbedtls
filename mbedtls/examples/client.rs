/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

#![feature(c_size_t)]

// needed to have common code for `mod support` in unit and integrations tests
extern crate mbedtls;

use clap::Parser;
use core::ffi::{c_char, c_int, c_size_t, c_uchar, c_uint};
use mbedtls::error::LoError::Asn1InvalidData;
use std::ffi::CStr;
use std::io::{self, stdin, stdout, Write};
use std::net::TcpStream;
use std::sync::Arc;

use mbedtls::rng::CtrDrbg;
use mbedtls::ssl::config::{Endpoint, Preset, Transport};
use mbedtls::ssl::{Config, Context};
use mbedtls::x509::{Certificate, VerifyError};
use mbedtls::Result as TlsResult;

#[path = "../tests/support/mod.rs"]
mod support;
use support::entropy::entropy_new;
use support::keys;

// FFI stuff for the functions defined in libra_tls_verify_dcap_gramine.so (if run in SGX enclave)
// and libra_tls_verify_dcap.so (if run outside of SGX enclave).
// See: https://github.com/gramineproject/gramine/blob/master/tools/sgx/ra-tls/ra_tls.h

// FFI for `ra_tls_verify_callback_extended_der` function

pub type RA_TLS_ATTESTATION_SCHEME_T = c_uint;
pub const RA_TLS_ATTESTATION_SCHEME_T_RA_TLS_ATTESTATION_SCHEME_UNKNOWN:
    RA_TLS_ATTESTATION_SCHEME_T = 0;
pub const RA_TLS_ATTESTATION_SCHEME_T_RA_TLS_ATTESTATION_SCHEME_EPID: RA_TLS_ATTESTATION_SCHEME_T =
    1;
pub const RA_TLS_ATTESTATION_SCHEME_T_RA_TLS_ATTESTATION_SCHEME_DCAP: RA_TLS_ATTESTATION_SCHEME_T =
    2;

pub type RA_TLS_ERR_LOC_T = c_uint;
pub const RA_TLS_ERR_LOC_T_AT_NONE: RA_TLS_ERR_LOC_T = 0;
pub const RA_TLS_ERR_LOC_T_AT_INIT: RA_TLS_ERR_LOC_T = 1;
pub const RA_TLS_ERR_LOC_T_AT_EXTRACT_QUOTE: RA_TLS_ERR_LOC_T = 2;
pub const RA_TLS_ERR_LOC_T_AT_VERIFY_EXTERNAL: RA_TLS_ERR_LOC_T = 3;
pub const RA_TLS_ERR_LOC_T_AT_VERIFY_ENCLAVE_ATTRS: RA_TLS_ERR_LOC_T = 4;
pub const RA_TLS_ERR_LOC_T_AT_VERIFY_ENCLAVE_MEASUREMENTS: RA_TLS_ERR_LOC_T = 5;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ra_tls_verify_callback_results_epid {
    pub ias_enclave_quote_status: [c_char; 128usize],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ra_tls_verify_callback_results_dcap {
    pub func_verify_quote_result: c_int,
    pub quote_verification_result: c_int,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ra_tls_verify_callback_results_misc {
    pub reserved: [c_char; 128usize],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union ra_tls_verify_callback_results_union {
    pub epid: ra_tls_verify_callback_results_epid,
    pub dcap: ra_tls_verify_callback_results_dcap,
    pub misc: ra_tls_verify_callback_results_misc,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ra_tls_verify_callback_results {
    pub attestation_scheme: RA_TLS_ATTESTATION_SCHEME_T,
    pub err_loc: RA_TLS_ERR_LOC_T, /* the step at which RA-TLS failed */
    pub __bindgen_anon_1: ra_tls_verify_callback_results_union,
}

extern "C" {
    /// Generic verification callback for EPID-based (IAS) or ECDSA-based (DCAP) quote verification
    /// (DER format) with additional information.
    ///
    /// * `der_crt`      - Self-signed RA-TLS certificate with SGX quote embedded in DER format.
    /// * `der_crt_size` - Size of the RA-TLS certificate.
    /// * `results`      - (Optional) Verification callback results for retrieving additional
    ///                    verification results from RA-TLS.
    ///
    /// Returns 0 on success, specific mbedTLS error code (negative int) otherwise. This function
    /// must be called from a non-mbedTLS verification callback, e.g., from a user-defined OpenSSL
    /// callback for SSL_CTX_set_cert_verify_callback(). All parameters required for the SGX quote,
    /// IAS attestation report verification, and/or DCAP quote verification must be passed in the
    /// corresponding RA-TLS environment variables.
    ///
    /// Originally defined as: int ra_tls_verify_callback_extended_der(uint8_t* der_crt, size_t
    ///   der_crt_size, struct ra_tls_verify_callback_results* results);
    ///
    /// See:
    /// https://raw.githubusercontent.com/gramineproject/gramine/master/tools/sgx/ra-tls/ra_tls.h
    pub fn ra_tls_verify_callback_extended_der(
        der_crt: *mut c_uchar,
        der_crt_size: c_size_t,
        results: *mut ra_tls_verify_callback_results,
    ) -> c_int;
}

// FFI for `ra_tls_set_measurement_callback` function

pub type verify_measurements_cb_t = Option<
    unsafe extern "C" fn(
        mrenclave: *const c_char,
        mrsigner: *const c_char,
        isv_prod_id: *const c_char,
        isv_svn: *const c_char,
    ) -> c_int,
>;

extern "C" {
    /// Callback for user-specific verification of measurements in SGX quote.
    ///
    /// * `f_cb` - Callback for user-specific verification; RA-TLS passes pointers to MRENCLAVE,
    ///            MRSIGNER, ISV_PROD_ID, ISV_SVN measurements in SGX quote. Use NULL to revert to
    ///            default behavior of RA-TLS.
    ///
    /// Returns 0 on success, specific error code (negative int) otherwise.
    ///
    /// If this callback is registered before RA-TLS session, then RA-TLS verification will invoke
    /// this callback to allow for user-specific checks on SGX measurements reported in the SGX
    /// quote. If no callback is registered (or registered as NULL), then RA-TLS defaults to
    /// verifying SGX measurements against `RA_TLS_*` environment variables (if any).
    pub fn ra_tls_set_measurement_callback(f_cb: verify_measurements_cb_t);
}

fn are_equal_u8_array_and_c_string(u8_array: &[u8], c_string_ptr: *const c_char) -> bool {
    // Convert the C string pointer to a Rust string
    let c_str_from_ptr = unsafe { CStr::from_ptr(c_string_ptr) };

    // Convert the array to a Rust string up to the null termination
    let arr_as_str = unsafe {
        let len = u8_array
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(u8_array.len());
        std::str::from_utf8_unchecked(&u8_array[..len])
    };

    // Compare the strings
    c_str_from_ptr.to_bytes() == arr_as_str.as_bytes()
}

static mut MRENCLAVE_ARR: [u8; 32] = [0; 32];
static mut MRSIGNER_ARR: [u8; 32] = [0; 32];
static mut ISV_PROD_ID_ARR: [u8; 2] = [0; 2];
static mut ISV_SVN_ARR: [u8; 2] = [0; 2];

// Define the callback function that matches the verify_measurements_cb_t type
unsafe extern "C" fn measurement_verification_callback(
    mrenclave: *const c_char,
    mrsigner: *const c_char,
    isv_prod_id: *const c_char,
    isv_svn: *const c_char,
) -> c_int {
    assert!(!mrenclave.is_null());
    assert!(!mrsigner.is_null());
    assert!(!isv_prod_id.is_null());
    assert!(!isv_svn.is_null());

    let pairs = [(&MRENCLAVE_ARR, mrenclave), (&MRSIGNER_ARR, mrsigner)];

    for &(arr, c_str_ptr) in &pairs {
        if are_equal_u8_array_and_c_string(arr, c_str_ptr) {
            return -1;
        }
    }

    let pairs2 = [(&ISV_PROD_ID_ARR, isv_prod_id), (&ISV_SVN_ARR, isv_svn)];

    for &(arr, c_str_ptr) in &pairs2 {
        if are_equal_u8_array_and_c_string(arr, c_str_ptr) {
            return -1;
        }
    }

    0
}

fn parse_hex(hex: &str, buffer: &mut [u8; 32]) -> Result<(), &'static str> {
    if hex.len() != buffer.len() * 2 {
        return Err("Hex string length does not match buffer size");
    }

    for i in 0..buffer.len() {
        let hex_byte = &hex[i * 2..i * 2 + 2];

        if !hex_byte.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("Invalid hexadecimal character detected");
        }

        if let Ok(parsed_byte) = u8::from_str_radix(hex_byte, 16) {
            buffer[i] = parsed_byte;
        } else {
            return Err("Failed to parse hexadecimal byte");
        }
    }

    Ok(())
}

// With raw/vanilla client
//
// ubuntu@VM-0-6-ubuntu:~/rust-mbedtls/target/debug/examples$ RUST_BACKTRACE=1 cargo run --example client 127.0.0.1:8080
// warning: /home/ubuntu/rust-mbedtls/mbedtls/Cargo.toml: version requirement `3.5.0-alpha.1+0b3de6f` for dependency `mbedtls-sys-auto` includes semver metadata which will be ignored, removing the metadata is recommended to avoid confusion
// warning: /home/ubuntu/rust-mbedtls/mbedtls-platform-support/Cargo.toml: version requirement `3.5.0-alpha.1+0b3de6f` for dependency `mbedtls-sys-auto` includes semver metadata which will be ignored, removing the metadata is recommended to avoid confusion
//     Finished dev [unoptimized + debuginfo] target(s) in 0.05s
// warning: the following packages contain code that will be rejected by a future version of Rust: traitobject v0.1.0
// note: to see what the problems were, use the option `--future-incompat-report`, or run `cargo report future-incompatibilities --id 1`
//      Running `./client '127.0.0.1:8080'`
// thread 'main' panicked at mbedtls/examples/client.rs:54:6:
// called `Result::unwrap()` on an `Err` value: HighLevel(X509CertVerifyFailed)
// stack backtrace:
//    0: rust_begin_unwind
//              at /rustc/e3abbd4994f72888f9e5e44dc89a4102e48c2a54/library/std/src/panicking.rs:619:5
//    1: core::panicking::panic_fmt
//              at /rustc/e3abbd4994f72888f9e5e44dc89a4102e48c2a54/library/core/src/panicking.rs:72:14
//    2: core::result::unwrap_failed
//              at /rustc/e3abbd4994f72888f9e5e44dc89a4102e48c2a54/library/core/src/result.rs:1652:5
//    3: core::result::Result<T,E>::unwrap
//              at /rustc/e3abbd4994f72888f9e5e44dc89a4102e48c2a54/library/core/src/result.rs:1077:23
//    4: client::main
//              at /home/ubuntu/rust-mbedtls/mbedtls/examples/client.rs:49:5
//    5: core::ops::function::FnOnce::call_once
//              at /rustc/e3abbd4994f72888f9e5e44dc89a4102e48c2a54/library/core/src/ops/function.rs:250:5
// note: Some details are omitted, run with `RUST_BACKTRACE=full` for a verbose backtrace.
fn result_main(addr: &str) -> TlsResult<()> {
    let entropy = Arc::new(entropy_new());
    let rng = Arc::new(CtrDrbg::new(entropy, None)?);
    let cert = Arc::new(Certificate::from_pem_multiple(
        keys::ROOT_CA_CERT.as_bytes(),
    )?);

    let verify_callback = move |crt: &Certificate, depth: i32, verify_flags: &mut VerifyError| {
        if depth != 0 {
            /* the cert chain in RA-TLS consists of single self-signed cert, so we expect depth 0 */
            // MBEDTLS_ERR_X509_INVALID_FORMAT;
            return Err(Asn1InvalidData.into());
        }
        if *verify_flags != VerifyError::empty() {
            /* mbedTLS sets flags to signal that the cert is not to be trusted (e.g., it is not
             * correctly signed by a trusted CA; since RA-TLS uses self-signed certs, we don't care
             * what mbedTLS thinks and ignore internal cert verification logic of mbedTLS */
            *verify_flags = VerifyError::empty();
        }
        let mut results: ra_tls_verify_callback_results = unsafe { std::mem::zeroed() };
        let mut der_data: Vec<u8> = crt.as_der().to_vec();
        let der_ptr = der_data.as_mut_ptr();
        let der_len = der_data.len();
        unsafe {
            let ret = ra_tls_verify_callback_extended_der(
                der_ptr,
                der_len,
                &mut results as *mut ra_tls_verify_callback_results,
            );
        }
        Ok(())

        // Test::CallbackSetVerifyFlags => {
        //     *verify_flags |= VerifyError::CERT_OTHER;
        //     Ok(())
        // }
        // Test::CallbackError => Err(codes::Asn1InvalidData.into()),
    };

    let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
    config.set_rng(rng);
    // https://github.com/fortanix/rust-mbedtls/blob/52476eed8af2824cc331acbd5ec84151a836291a/mbedtls/tests/ssl_conf_verify.rs#L53C25-L54C49
    config.set_verify_callback(verify_callback);
    config.set_ca_list(cert, None);
    let mut ctx = Context::new(Arc::new(config));

    let conn = TcpStream::connect(addr).unwrap();
    ctx.establish(conn, None)?;

    let mut line = String::new();
    stdin().read_line(&mut line).unwrap();
    ctx.write_all(line.as_bytes()).unwrap();
    io::copy(&mut ctx, &mut stdout()).unwrap();
    Ok(())
}

#[derive(Parser)]
struct Cli {
    address: String,
    mrenclave: String,
    mrsigner: String,
    isv_prod_id: u8,
    isv_svn: u16,
}

// ./client a 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff 3 4
// https://github.com/fortanix/rust-mbedtls/blob/52476eed8af2824cc331acbd5ec84151a836291a/mbedtls/tests/ssl_conf_verify.rs#L19
fn main() {
    let args = Cli::parse();

    unsafe {
        match parse_hex(&args.mrenclave, &mut MRENCLAVE_ARR) {
            Ok(_) => println!(
                "Mrenclave hex string parsed successfully: {:?}",
                MRENCLAVE_ARR
            ),
            Err(err) => println!("Error: {}", err),
        }

        match parse_hex(&args.mrsigner, &mut MRSIGNER_ARR) {
            Ok(_) => println!(
                "Mrsigner hex string parsed successfully: {:?}",
                MRSIGNER_ARR
            ),
            Err(err) => println!("Error: {}", err),
        }

        ISV_PROD_ID_ARR.copy_from_slice(&args.isv_prod_id.to_le_bytes());
        ISV_SVN_ARR.copy_from_slice(&args.isv_svn.to_le_bytes());
    }

    println!("Before");
    // convert args to the expected format
    unsafe {
        ra_tls_set_measurement_callback(Some(measurement_verification_callback));
    }
    println!(
        "[ using our own SGX-measurement verification callback (via command line options) ]\n"
    );

    result_main(&args.address).unwrap();
}
