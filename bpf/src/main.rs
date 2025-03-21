// SPDX-License-Identifier: GPL-2.0
mod bpf;
use bpf::*;

use libbpf_rs::skel::*;
use std::mem::MaybeUninit;

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use clap::{Parser, ValueEnum};

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Cli {
    /// Verifier log level
    #[arg(long, value_enum)]
    verifier_log_level: VerifierLogLevel,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum VerifierLogLevel {
    None = 0,
    Info = 1,
    Verbose = 2,
}

fn main() {
    let cli = Cli::parse();

    let mut open_object = MaybeUninit::uninit();
    let skel_builder = ExampleSkelBuilder::default();

    let kernel_log_size = 10000000;
    let mut kernel_log_buf = vec![0i8; kernel_log_size].into_boxed_slice();
    let ptr: *mut i8 = kernel_log_buf.as_mut_ptr();

    let mut open_opts = libbpf_sys::bpf_object_open_opts::default();
    open_opts.sz = std::mem::size_of::<libbpf_sys::bpf_object_open_opts>() as u64;
    open_opts.kernel_log_buf = ptr;
    open_opts.kernel_log_size = kernel_log_size as u64;
    open_opts.kernel_log_level = match cli.verifier_log_level {
        VerifierLogLevel::None => 0,
        VerifierLogLevel::Info => 1,
        VerifierLogLevel::Verbose => 1 | 2,
    };
    let open_skel = skel_builder.open_opts(open_opts, &mut open_object).unwrap();
    let skel = open_skel.load();

    // The kernel log ends with "\0\0", so we look for a place
    // where two NULL bytes appear consecutively.
    let mut prev_null = false;
    for c in kernel_log_buf {
        print!("{}", c as u8 as char);

        if c == 0 {
            if prev_null {
                break;
            }
            prev_null = true;
        } else {
            prev_null = false;
        }
    }

    let mut skel = if skel.is_err() {
	    return;
    } else {
	    skel.unwrap()
    };

    let _link = skel.maps.my_ops_sample.attach_struct_ops().unwrap();
    println!("Successfully attached bpf program!");

    // Register Ctrl+C handler that terminate this app
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        println!("Ctrl+C is sent!");
        shutdown_clone.store(true, Ordering::Relaxed);
    }).expect("Error setting Ctrl+C handler");

    while !shutdown.load(Ordering::Relaxed) {
        let duration = std::time::Duration::from_millis(100);
        std::thread::sleep(duration);
    }
    println!("Shutdown..");
}
