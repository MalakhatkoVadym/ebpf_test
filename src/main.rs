use anyhow::bail;
use anyhow::Result;
use core::time::Duration;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::PerfBufferBuilder;
use plain::Plain;
use std::fs::File;
use std::io::prelude::*;
use std::sync::{Arc, Mutex};
use time::macros::format_description;
use time::OffsetDateTime;

mod testhook {
    include!(concat!(env!("OUT_DIR"), "/testhook.skel.rs"));
}

use testhook::*;

unsafe impl Plain for testhook_bss_types::event {}

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}

fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("Lost {count} events on CPU {cpu}");
}

fn main() -> Result<()> {
    let skel_builder = TesthookSkelBuilder::default();

    bump_memlock_rlimit()?;

    let open_skel = skel_builder.open()?;

    let mut skel = open_skel.load()?;
    skel.attach()?;

    let file = Arc::new(Mutex::new(
        File::create("output.txt").expect("Unable to create file"),
    ));

    let file_clone = file.clone();
    let handle_event = move |_cpu: i32, data: &[u8]| {
        let mut event = testhook_bss_types::event::default();
        plain::copy_from_bytes(&mut event, data).expect("Data buffer was too short");
        let now = if let Ok(now) = OffsetDateTime::now_local() {
            let format = format_description!("[hour]:[minute]:[second]");
            now.format(&format)
                .unwrap_or_else(|_| "00:00:00".to_string())
        } else {
            "00:00:00".to_string()
        };
        let mut locked_file = file_clone.lock().unwrap();
        write!(locked_file, "{:9} {:<6} \n", now, event.pid,).unwrap();
    };
    let perf = PerfBufferBuilder::new(skel.maps_mut().events())
        .sample_cb(handle_event)
        .lost_cb(handle_lost_events)
        .build()?;

    loop {
        perf.poll(Duration::from_millis(100))?;
    }
}
