//! Dev receiver: ingests concatenated diode frames from stdin and writes append-only artifacts.
//! No acknowledgments; one-way only.

use std::env;
use std::io::{self, Read};
use std::path::PathBuf;

use ro_out_receiver::{ingest_stream, write_manifest, AppendStore};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;

    let root = env::var("RO_OUT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("artifacts/enterprise"));
    let store = AppendStore::new(root)?;

    ingest_stream(&store, &input)?;
    write_manifest(&store)?;

    Ok(())
}
