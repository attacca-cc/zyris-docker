//! System state sampling, read straight from Linux `/proc`.
//!
//! This node runs inside a container on Linux, so there is no need for a system-information crate:
//! `/proc/stat`, `/proc/meminfo`, `/proc/loadavg`, `/proc/uptime` and `/proc/<pid>/stat` carry
//! everything, and reading them has no native dependency to build.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// A point-in-time snapshot of the host the node runs on.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SystemSnapshot {
    /// Hostname as the kernel sees it.
    pub hostname: String,
    /// Uptime in seconds since boot.
    pub uptime_secs: u64,
    /// CPU utilisation as a percentage of one core (0–100; 400 = four cores fully busy).
    pub cpu_percent: f32,
    /// 1-, 5- and 15-minute load averages.
    pub load_avg: [f32; 3],
    /// Total physical memory in bytes.
    pub mem_total_bytes: u64,
    /// Physical memory in use in bytes.
    pub mem_used_bytes: u64,
    /// Memory currently available to new processes, in bytes.
    pub mem_available_bytes: u64,
    /// Swap total in bytes.
    pub swap_total_bytes: u64,
    /// Swap in use in bytes.
    pub swap_used_bytes: u64,
    /// Number of running processes visible in this container's PID namespace.
    pub process_count: u64,
    /// Root filesystem total bytes (the filesystem holding `/`).
    pub disk_total_bytes: u64,
    /// Root filesystem used bytes.
    pub disk_used_bytes: u64,
}

/// One process in the container's PID namespace.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProcessInfo {
    pub pid: i32,
    /// Process name (`/proc/<pid>/comm`), truncated to 15 chars by the kernel.
    pub name: String,
    /// Kernel scheduling state, e.g. `R` (running), `S` (sleeping), `D` (uninterruptible), `Z` (zombie).
    pub state: String,
    /// Resident set size (physical memory) in bytes.
    pub rss_bytes: u64,
    /// Cumulative CPU time in seconds (process + children).
    pub cpu_secs: u64,
    /// The command line, joined with spaces. Empty for a kernel thread.
    pub cmdline: String,
}

fn read_file(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// The cpu + all-cpu aggregate lines from `/proc/stat`, as (user, nice, system, idle, iowait, irq, softirq, steal).
fn cpu_times() -> (u64, u64, u64, u64) {
    let mut totals = (0u64, 0u64, 0u64, 0u64);
    for line in read_file("/proc/stat").lines() {
        let mut it = line.split_whitespace();
        if it.next() == Some("cpu") {
            // cpu  user nice system idle iowait irq softirq steal
            let v: Vec<u64> = it.take(8).filter_map(|s| s.parse().ok()).collect();
            if v.len() >= 4 {
                let (user, nice, system, idle) = (v[0], v[1], v[2], v[3]);
                totals = (user, nice, system, idle);
            }
        }
    }
    totals
}

fn cpu_percent() -> f32 {
    let (u1, n1, s1, i1) = cpu_times();
    let idle1 = i1;
    let busy1 = u1 + n1 + s1;
    // Sample twice ~200ms apart and take the delta, like `top`.
    std::thread::sleep(std::time::Duration::from_millis(200));
    let (u2, n2, s2, i2) = cpu_times();
    let idle2 = i2;
    let busy2 = u2 + n2 + s2;
    let d_busy = busy2.saturating_sub(busy1) as f32;
    let d_total = (d_busy + (idle2.saturating_sub(idle1)) as f32).max(1.0);
    (d_busy / d_total) * 100.0
}

/// Parse a keyed `/proc/meminfo` value (kB) into bytes, looking up `key`.
fn meminfo_kb(key: &str) -> u64 {
    read_file("/proc/meminfo")
        .lines()
        .find(|l| l.starts_with(key))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse::<u64>().ok())
        .map(|kb| kb * 1024)
        .unwrap_or(0)
}

fn load_avg() -> [f32; 3] {
    let raw = read_file("/proc/loadavg");
    let mut out = [0f32; 3];
    for (i, field) in raw.split_whitespace().take(3).enumerate() {
        out[i] = field.parse().unwrap_or(0.0);
    }
    out
}

fn uptime_secs() -> u64 {
    read_file("/proc/uptime")
        .split_whitespace()
        .next()
        .and_then(|v| v.parse::<f64>().ok())
        .map(|s| s as u64)
        .unwrap_or(0)
}

fn disk_usage() -> (u64, u64) {
    #[cfg(target_os = "linux")]
    {
        use std::mem::MaybeUninit;
        let mut stat: MaybeUninit<libc::statvfs> = MaybeUninit::uninit();
        let rc = unsafe { libc::statvfs(c"/".as_ptr(), stat.as_mut_ptr()) };
        if rc == 0 {
            let s = unsafe { stat.assume_init() };
            let block = s.f_bsize;
            let total = s.f_blocks * block;
            let free = s.f_bfree * block;
            return (total, total.saturating_sub(free));
        }
        (0, 0)
    }
    #[cfg(not(target_os = "linux"))]
    {
        (0, 0)
    }
}

/// Whether a process with exactly this `comm` name is alive in this PID namespace.
pub fn process_running(name: &str) -> bool {
    process_list().iter().any(|p| p.name == name)
}

/// List every process visible in this container's PID namespace.
pub fn process_list() -> Vec<ProcessInfo> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else { return out };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_string_lossy().parse::<i32>().ok() else { continue };
        let stat_path = entry.path().join("stat");
        let Ok(stat) = std::fs::read_to_string(&stat_path) else { continue };
        if let Some(p) = parse_proc_stat(pid, &stat, &entry.path()) { out.push(p); }
    }
    out
}

/// Parse `/proc/<pid>/stat`. The tricky bit is that the comm field is `(name)` and may itself
/// contain spaces and `)` — so split on the *last* `)` instead of on whitespace.
fn parse_proc_stat(pid: i32, stat: &str, dir: &Path) -> Option<ProcessInfo> {
    let (head, tail) = stat.split_once(')')?;
    let comm = head.rsplit_once('(').map(|(_, c)| c.trim()).unwrap_or("").to_string();
    let fields: Vec<&str> = tail.split_whitespace().collect();
    // After `)`, the fields start at state: index 0 => state, 22 => starttime, 23 => vsize, 24 => rss,
    // 14 => utime, 15 => stime, 16 => cutime, 17 => cstime.
    let state = fields.first().map(|s| s.to_string()).unwrap_or_default();
    let rss_pages = fields.get(23).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
    let utime = fields.get(14).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
    let stime = fields.get(15).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
    let cutime = fields.get(16).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
    let cstime = fields.get(17).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
    let cpu_secs = (utime + stime + cutime + cstime) / 100; // clock ticks (100/s on Linux)
    let cmdline = std::fs::read(dir.join("cmdline"))
        .map(|bytes| {
            bytes
                .split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();
    Some(ProcessInfo {
        pid,
        name: comm,
        state,
        rss_bytes: rss_pages * 4096,
        cpu_secs,
        cmdline,
    })
}

/// A full system snapshot.
pub fn system_snapshot() -> SystemSnapshot {
    let hostname = read_file("/proc/sys/kernel/hostname").trim().to_string();
    let mem_total = meminfo_kb("MemTotal:");
    let mem_avail = meminfo_kb("MemAvailable:");
    let mem_used = mem_total.saturating_sub(mem_avail);
    let swap_total = meminfo_kb("SwapTotal:");
    let swap_free = meminfo_kb("SwapFree:");
    let swap_used = swap_total.saturating_sub(swap_free);
    let (disk_total, disk_used) = disk_usage();
    SystemSnapshot {
        hostname,
        uptime_secs: uptime_secs(),
        cpu_percent: cpu_percent(),
        load_avg: load_avg(),
        mem_total_bytes: mem_total,
        mem_used_bytes: mem_used,
        mem_available_bytes: mem_avail,
        swap_total_bytes: swap_total,
        swap_used_bytes: swap_used,
        process_count: process_list().len() as u64,
        disk_total_bytes: disk_total,
        disk_used_bytes: disk_used,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proc_stat_with_spaces_in_comm() {
        let stat = "1234 (my cool proc) S 1 2 3 4 5 6 0 0 0 0 0 0 0 100 50 0 10 0 0 0 0 0 100 200 0";
        let p = parse_proc_stat(1234, stat, Path::new("/nonexistent")).unwrap();
        assert_eq!(p.name, "my cool proc");
        assert_eq!(p.state, "S");
        assert_eq!(p.rss_bytes, 100 * 4096);
        assert_eq!(p.cpu_secs, (100 + 50 + 10) / 100);
    }
}
