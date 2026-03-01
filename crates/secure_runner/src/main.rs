//! Boundary-safe diode emitter.
//! Emits a single RecordFrame to stdout (raw bytes). No logging, no stdin, no filesystem, no time, no randomness.

use std::env;
use std::io::{self, Write};
use std::process;

use secure_runner::{build_frame, Bucket};

fn main() {
    if let Err(err) = run() {
        // Fail closed: emit nothing on stdout; minimal stderr to aid operator outside boundary.
        let _ = writeln!(io::stderr(), "secure_runner error: {err}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut bucket = Bucket::Audit;
    let mut tick: u64 = 0;
    let mut payload_hex: Option<String> = None;

    let mut args = env::args().skip(1).collect::<Vec<_>>();
    if args.first().map(String::as_str) == Some("emit") {
        args.remove(0);
    }

    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--bucket" => {
                let val = iter.next().ok_or("--bucket requires value")?;
                bucket = parse_bucket(&val)?;
            }
            "--tick" => {
                let val = iter.next().ok_or("--tick requires value")?;
                tick = val.parse().map_err(|_| "invalid tick")?;
            }
            "--payload-hex" => {
                let val = iter.next().ok_or("--payload-hex requires value")?;
                payload_hex = Some(val);
            }
            other => return Err(format!("unknown arg: {other}")),
        }
    }

    let payload = if let Some(h) = payload_hex {
        hex::decode(h).map_err(|_| "invalid hex payload")?
    } else {
        Vec::new()
    };

    let frame = build_frame(bucket, tick, payload).map_err(|e| format!("frame build: {e:?}"))?;
    let bytes = frame.encode().map_err(|e| format!("encode: {e:?}"))?;
    let mut stdout = io::stdout();
    stdout
        .write_all(&bytes)
        .map_err(|e| format!("write stdout: {e}"))?;
    stdout.flush().map_err(|e| format!("flush stdout: {e}"))?;
    Ok(())
}

fn parse_bucket(value: &str) -> Result<Bucket, String> {
    match value {
        "audit" => Ok(Bucket::Audit),
        "metrics" => Ok(Bucket::Metrics),
        "security" => Ok(Bucket::Security),
        "outputs" => Ok(Bucket::Outputs),
        _ => Err("invalid bucket".into()),
    }
}
