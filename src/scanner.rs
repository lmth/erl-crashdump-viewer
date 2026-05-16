//! Line-by-line section scanner for Erlang crash dump files.
//!
//! Transparently handles plain-text, zstd-, gzip-, and xz-compressed dumps
//! (detected by magic bytes, not file extension).
//!
//! `Scanner::new` opens a file path; `Scanner::from_reader` accepts any
//! `Read` source (e.g. a streaming channel for concurrent upload+parse).

use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::path::Path;

const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];
const GZIP_MAGIC: [u8; 2] = [0x1F, 0x8B];
const XZ_MAGIC:   [u8; 6] = [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00];

pub enum Event {
    NewSection { kind: String, key: Option<String> },
    DataLine(String),
}

pub struct Scanner {
    reader: Box<dyn BufRead>,
    line_buf: String,
}

impl Scanner {
    pub fn new(path: &Path) -> io::Result<Self> {
        Self::from_reader(File::open(path)?)
    }

    /// Build a scanner from any `Read` source.
    ///
    /// Magic-byte detection is done by peeking into `BufReader::fill_buf`,
    /// which fills the internal buffer without advancing the read position —
    /// so the bytes are still present when the decoder starts reading.
    pub fn from_reader(reader: impl Read + 'static) -> io::Result<Self> {
        let mut buf = BufReader::with_capacity(65536, reader);
        let magic = {
            let filled = buf.fill_buf()?;
            let mut m = [0u8; 6];
            let n = filled.len().min(6);
            m[..n].copy_from_slice(&filled[..n]);
            m
        };
        let reader: Box<dyn BufRead> = if magic[..4] == ZSTD_MAGIC {
            Box::new(BufReader::new(zstd::Decoder::new(buf)?))
        } else if magic[..2] == GZIP_MAGIC {
            Box::new(BufReader::new(flate2::read::GzDecoder::new(buf)))
        } else if magic[..6] == XZ_MAGIC {
            Box::new(BufReader::new(xz2::read::XzDecoder::new(buf)))
        } else {
            Box::new(buf)
        };
        Ok(Scanner { reader, line_buf: String::with_capacity(256) })
    }
}

impl Iterator for Scanner {
    type Item = io::Result<Event>;

    fn next(&mut self) -> Option<Self::Item> {
        self.line_buf.clear();
        match self.reader.read_line(&mut self.line_buf) {
            Ok(0) => None,
            Err(e) => Some(Err(e)),
            Ok(_) => {
                let line = self.line_buf.trim_end_matches(['\n', '\r']);
                if let Some(rest) = line.strip_prefix('=') {
                    let (kind, key) = match rest.find(':') {
                        Some(i) => (rest[..i].to_string(), Some(rest[i + 1..].to_string())),
                        None => (rest.to_string(), None),
                    };
                    Some(Ok(Event::NewSection { kind, key }))
                } else {
                    Some(Ok(Event::DataLine(line.to_string())))
                }
            }
        }
    }
}
