#![cfg(windows)]

use anyhow::{bail, Context, Result};
use memchr::memmem;
use std::collections::HashSet;
use std::mem::size_of;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_READONLY, PAGE_READWRITE,
    PAGE_WRITECOPY,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

const SCAN_CHUNK_SIZE: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct Region {
    pub base: usize,
    pub size: usize,
}

#[derive(Debug, Clone, Copy)]
struct ProcessInfo {
    pid: u32,
    parent_pid: u32,
    thread_count: u32,
}

pub struct ProcessReader {
    handle: HANDLE,
    regions: Vec<Region>,
}

impl ProcessReader {
    pub fn open(pid: u32) -> Result<Self> {
        let handle =
            unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) }
                .with_context(|| {
                    format!("cannot open Weixin.exe pid {pid} for read-only inspection")
                })?;

        let regions = query_readable_regions(handle);
        if regions.is_empty() {
            unsafe {
                let _ = CloseHandle(handle);
            }
            bail!("no readable memory regions found in pid {pid}");
        }

        Ok(Self { handle, regions })
    }

    pub fn regions(&self) -> &[Region] {
        &self.regions
    }

    pub fn read(&self, address: usize, size: usize) -> Option<Vec<u8>> {
        if size == 0 || !self.contains_range(address, size) {
            return None;
        }

        let mut buffer = vec![0u8; size];
        let mut bytes_read = 0usize;
        let result = unsafe {
            ReadProcessMemory(
                self.handle,
                address as _,
                buffer.as_mut_ptr() as _,
                size,
                Some(&mut bytes_read),
            )
        };

        if !result.as_bool() || bytes_read != size {
            return None;
        }
        Some(buffer)
    }

    pub fn scan(&self, needles: &[Vec<u8>], max_matches: usize) -> Vec<Vec<usize>> {
        let mut matches = vec![Vec::new(); needles.len()];
        let max_needle = needles.iter().map(Vec::len).max().unwrap_or(1);

        for region in &self.regions {
            let mut offset = 0usize;
            let mut overlap = Vec::new();

            while offset < region.size {
                if matches.iter().map(Vec::len).sum::<usize>() >= max_matches {
                    return matches;
                }

                let requested = SCAN_CHUNK_SIZE.min(region.size - offset);
                let Some(chunk) = self.read(region.base + offset, requested) else {
                    offset += requested;
                    overlap.clear();
                    continue;
                };

                let overlap_len = overlap.len();
                let mut data = overlap;
                data.extend_from_slice(&chunk);
                let logical_base = region.base + offset - overlap_len;

                for (needle_index, needle) in needles.iter().enumerate() {
                    if needle.is_empty() {
                        continue;
                    }
                    for found in memmem::find_iter(&data, needle) {
                        let address = logical_base + found;
                        if address >= region.base && !matches[needle_index].contains(&address) {
                            matches[needle_index].push(address);
                        }
                    }
                }

                let keep = max_needle.saturating_sub(1).min(data.len());
                overlap = data[data.len() - keep..].to_vec();
                offset += requested;
            }
        }

        matches
    }

    pub fn contains_range(&self, address: usize, size: usize) -> bool {
        let Some(end) = address.checked_add(size) else {
            return false;
        };
        self.regions
            .iter()
            .any(|region| address >= region.base && end <= region.base.saturating_add(region.size))
    }

    /// Broad scan: walk every readable memory region and collect every 8‑byte‑aligned
    /// 32‑byte sequence that passes `looks_like_key`.
    pub fn broad_scan(
        &self,
        looks_like_key: impl Fn(&[u8; 32]) -> bool,
        max_matches: usize,
    ) -> Vec<[u8; 32]> {
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        let mut results = Vec::with_capacity(max_matches);

        for region in &self.regions {
            if results.len() >= max_matches {
                break;
            }
            let mut offset = 0usize;
            while offset + 32 <= region.size && results.len() < max_matches {
                let chunk_size = SCAN_CHUNK_SIZE.min(region.size - offset);
                let Some(chunk) = self.read(region.base + offset, chunk_size) else {
                    offset += chunk_size;
                    continue;
                };
                for idx in (0..chunk.len().saturating_sub(32)).step_by(8) {
                    if !fast_key_filter(&chunk[idx..idx + 32]) {
                        continue;
                    }
                    let mut candidate = [0u8; 32];
                    candidate.copy_from_slice(&chunk[idx..idx + 32]);
                    if looks_like_key(&candidate) && seen.insert(candidate) {
                        results.push(candidate);
                        if results.len() >= max_matches {
                            break;
                        }
                    }
                }
                offset += chunk_size;
            }
        }
        results
    }
}

impl Drop for ProcessReader {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

pub fn find_main_weixin_pid() -> Result<u32> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
        .context("cannot enumerate Windows processes")?;

    let result = (|| {
        let mut entry = PROCESSENTRY32::default();
        entry.dwSize = size_of::<PROCESSENTRY32>() as u32;
        if !unsafe { Process32First(snapshot, &mut entry) }.as_bool() {
            bail!("cannot read the Windows process list");
        }

        let mut candidates = Vec::new();
        loop {
            if process_name(&entry).eq_ignore_ascii_case("Weixin.exe") {
                candidates.push(ProcessInfo {
                    pid: entry.th32ProcessID,
                    parent_pid: entry.th32ParentProcessID,
                    thread_count: entry.cntThreads,
                });
            }

            if !unsafe { Process32Next(snapshot, &mut entry) }.as_bool() {
                break;
            }
        }

        if candidates.is_empty() {
            bail!("Weixin.exe is not running");
        }

        let pids: HashSet<u32> = candidates.iter().map(|process| process.pid).collect();
        candidates.sort_by_key(|process| {
            (
                pids.contains(&process.parent_pid),
                std::cmp::Reverse(process.thread_count),
            )
        });
        Ok(candidates[0].pid)
    })();

    unsafe {
        let _ = CloseHandle(snapshot);
    }
    result
}

fn process_name(entry: &PROCESSENTRY32) -> String {
    let end = entry
        .szExeFile
        .iter()
        .position(|byte| byte.0 == 0)
        .unwrap_or(entry.szExeFile.len());
    let bytes: Vec<u8> = entry.szExeFile[..end]
        .iter()
        .map(|byte| byte.0 as u8)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn query_readable_regions(handle: HANDLE) -> Vec<Region> {
    let mut regions = Vec::new();
    let mut address = 0usize;

    loop {
        let mut info = MEMORY_BASIC_INFORMATION::default();
        let queried = unsafe {
            VirtualQueryEx(
                handle,
                Some(address as _),
                &mut info,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if queried == 0 {
            break;
        }

        let base = info.BaseAddress as usize;
        let size = info.RegionSize;
        if info.State == MEM_COMMIT && is_readable(info.Protect.0) && size > 0 {
            regions.push(Region { base, size });
        }

        let next = base.saturating_add(size);
        if next <= address || size == 0 {
            break;
        }
        address = next;
    }

    regions
}

fn is_readable(protection: u32) -> bool {
    if protection & PAGE_GUARD.0 != 0 {
        return false;
    }
    let base = protection & 0xff;
    [
        PAGE_READONLY.0,
        PAGE_READWRITE.0,
        PAGE_WRITECOPY.0,
        PAGE_EXECUTE_READ.0,
        PAGE_EXECUTE_READWRITE.0,
        PAGE_EXECUTE_WRITECOPY.0,
    ]
    .contains(&base)
}

/// Quick entropy pre‑check: reject byte sequences that are clearly not keys
/// (all‑zeros, repeated byte, low entropy).  Returns `true` when the 32‑bytes
/// warrant a full `looks_like_key` evaluation.
fn fast_key_filter(bytes: &[u8]) -> bool {
    if bytes.len() < 32 {
        return false;
    }
    let first = bytes[0];
    if first == 0 {
        return false;
    }
    // Map each byte to a bit in a 32‑bit mask; require ≥ 10 distinct low‑5‑bit
    // values (≈ 3.3 bits of entropy = 5.7 distinct values on average for random).
    let mut bits = 0u32;
    for &b in &bytes[..32] {
        bits |= 1u32 << (b & 31);
    }
    bits.count_ones() >= 10
}
