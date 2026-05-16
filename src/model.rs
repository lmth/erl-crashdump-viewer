//! Data model types returned by `DumpReader`.

use crate::termdecoder::ErlTerm;

// ─── Process ─────────────────────────────────────────────────────────────────

/// Summary of a process — everything from the `=proc:Pid` text section.
#[derive(Debug, Clone)]
pub struct ProcessSummary {
    pub pid: String,
    pub name: Option<String>,
    pub state: String,
    pub spawned_as: Option<String>,
    pub spawned_by: Option<String>,
    pub mqueue_len: u64,
    /// Stack + heap words
    pub stack_heap: u64,
    /// Old-generation heap words
    pub old_heap: u64,
    /// Unused words in young heap
    pub heap_unused: u64,
    /// Total process memory in bytes
    pub memory: u64,
    pub reductions: u64,
    pub program_counter: Option<String>,
    pub arity: u32,
    pub links: Vec<String>,
    pub monitors: Vec<String>,
}

/// A single entry in a process stack dump.
#[derive(Debug, Clone)]
pub struct StackEntry {
    /// Register label, e.g. `y0`, `0x7f...`
    pub label: String,
    /// Decoded term, or `None` for info lines (return addrs, catch labels)
    pub term: Option<ErlTerm>,
    /// Raw encoded string (for fallback display)
    pub raw: String,
}

/// Full process details: summary + decoded stack, dictionary, messages.
#[derive(Debug, Clone)]
pub struct ProcessDetails {
    pub summary: ProcessSummary,
    pub stack: Vec<StackEntry>,
    pub dictionary: Vec<ErlTerm>,
    pub messages: Vec<ErlTerm>,
}

/// A paginated slice of results with the total count of available items.
#[derive(Debug, Clone)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
}

impl<T> Page<T> {
    pub fn empty(offset: usize, limit: usize) -> Self {
        Page { items: vec![], total: 0, offset, limit }
    }
    pub fn has_prev(&self) -> bool { self.offset > 0 }
    pub fn has_next(&self) -> bool { self.offset + self.items.len() < self.total }
    pub fn prev_offset(&self) -> usize { self.offset.saturating_sub(self.limit) }
    pub fn next_offset(&self) -> usize { self.offset + self.limit }
}

// ─── Memory ──────────────────────────────────────────────────────────────────

/// System memory overview from the `=memory` section.
#[derive(Debug, Clone, Default)]
pub struct MemoryInfo {
    pub entries: Vec<(String, u64)>,
}

impl MemoryInfo {
    pub fn get(&self, key: &str) -> Option<u64> {
        self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| *v)
    }
}

// ─── ETS ─────────────────────────────────────────────────────────────────────

/// Summary of one ETS table from the `=ets:OwnerPid` section.
#[derive(Debug, Clone)]
pub struct EtsTable {
    pub owner_pid: String,
    pub name: String,
    pub table_type: String,
    pub protection: String,
    pub objects: u64,
    pub words: u64,
    pub buckets: Option<u64>,
    pub write_concurrency: bool,
    pub read_concurrency: bool,
    pub compressed: bool,
    pub fixed: bool,
}
