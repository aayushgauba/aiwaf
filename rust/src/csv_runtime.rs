//! Native CSV parsing/writing with file locks and metadata-validated snapshots.
//! Lock the data inode (not a sidecar) to interoperate with Python's flock users.
use fs2::FileExt;
use pyo3::{exceptions::PyIOError, prelude::*};
use std::{
    collections::{HashMap, HashSet},
    fs::{File, OpenOptions},
    io::{Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
    time::SystemTime,
};

type Table = (Vec<String>, Vec<Vec<String>>);
type Snapshot = (Stamp, Table, HashMap<String, HashMap<String, usize>>);
#[derive(Clone, PartialEq)]
struct Stamp {
    len: u64,
    modified: Option<SystemTime>,
    created: Option<SystemTime>,
    #[cfg(unix)]
    identity: (u64, u64, i64, i64),
}
fn stamp(file: &File) -> std::io::Result<Stamp> {
    let meta = file.metadata()?;
    Ok(Stamp {
        len: meta.len(),
        modified: meta.modified().ok(),
        created: meta.created().ok(),
        #[cfg(unix)]
        identity: {
            use std::os::unix::fs::MetadataExt;
            (meta.dev(), meta.ino(), meta.ctime(), meta.ctime_nsec())
        },
    })
}
static CACHE: OnceLock<Mutex<HashMap<PathBuf, Snapshot>>> = OnceLock::new();
fn cache() -> &'static Mutex<HashMap<PathBuf, Snapshot>> {
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}
fn error(e: impl std::fmt::Display) -> PyErr {
    PyIOError::new_err(e.to_string())
}
fn parse(file: &File) -> PyResult<Table> {
    let mut reader = csv::ReaderBuilder::new().flexible(true).from_reader(file);
    let headers = reader
        .headers()
        .map_err(error)?
        .iter()
        .map(str::to_owned)
        .collect();
    let rows = reader
        .records()
        .map(|r| {
            r.map(|row| row.iter().map(str::to_owned).collect())
                .map_err(error)
        })
        .collect::<PyResult<_>>()?;
    Ok((headers, rows))
}
fn with_snapshot<T>(
    path: &str,
    use_cache: bool,
    operation: impl FnOnce(&mut Snapshot) -> PyResult<T>,
) -> PyResult<T> {
    let file = File::open(path).map_err(error)?;
    FileExt::lock_shared(&file).map_err(error)?;
    let key = Path::new(path).canonicalize().map_err(error)?;
    let current = stamp(&file).map_err(error)?;
    let mut snapshots = cache().lock().map_err(error)?;
    if !use_cache || snapshots.get(&key).map(|(s, _, _)| s) != Some(&current) {
        let table = parse(&file)?;
        // Bound memory used by applications that create many data directories.
        if snapshots.len() >= 128 {
            snapshots.clear();
        }
        if use_cache {
            snapshots.insert(key.clone(), (current, table, HashMap::new()));
        } else {
            return operation(&mut (current, table, HashMap::new()));
        }
    }
    operation(snapshots.get_mut(&key).unwrap())
    // Closing the file releases its flock/Windows lock, including on error.
}

fn with_table<T>(
    path: &str,
    use_cache: bool,
    operation: impl FnOnce(&Table) -> PyResult<T>,
) -> PyResult<T> {
    with_snapshot(path, use_cache, |snapshot| operation(&snapshot.1))
}

fn indexed_row<'a>(snapshot: &'a mut Snapshot, field: &str, key: &str) -> Option<&'a Vec<String>> {
    let index = snapshot.1 .0.iter().position(|h| h == field)?;
    let lookup = snapshot.2.entry(field.to_owned()).or_insert_with(|| {
        snapshot
            .1
             .1
            .iter()
            .enumerate()
            .filter_map(|(i, row)| row.get(index).map(|v| (v.trim().to_owned(), i)))
            .collect()
    });
    lookup.get(key).and_then(|i| snapshot.1 .1.get(*i))
}

#[pyfunction]
pub fn csv_read(py: Python<'_>, path: String, use_cache: bool) -> PyResult<Table> {
    py.allow_threads(|| with_table(&path, use_cache, |table| Ok(table.clone())))
}

#[pyfunction]
pub fn csv_contains(
    py: Python<'_>,
    path: String,
    key_field: String,
    key: String,
    use_cache: bool,
) -> PyResult<bool> {
    py.allow_threads(|| {
        with_snapshot(&path, use_cache, |snapshot| {
            Ok(indexed_row(snapshot, &key_field, &key).is_some())
        })
    })
}

#[pyfunction]
pub fn csv_read_set(
    py: Python<'_>,
    path: String,
    key_field: String,
    use_cache: bool,
) -> PyResult<HashSet<String>> {
    py.allow_threads(|| {
        with_table(&path, use_cache, |(headers, rows)| {
            let Some(index) = headers.iter().position(|h| h == &key_field) else {
                return Ok(HashSet::new());
            };
            Ok(rows
                .iter()
                .filter_map(|row| row.get(index))
                .filter(|v| !v.is_empty())
                .map(|v| v.trim().to_owned())
                .collect())
        })
    })
}

#[pyfunction]
pub fn csv_read_dict(
    py: Python<'_>,
    path: String,
    key_field: String,
    value_field: String,
    use_cache: bool,
) -> PyResult<HashMap<String, String>> {
    py.allow_threads(|| {
        with_table(&path, use_cache, |(headers, rows)| {
            let Some(index) = headers.iter().position(|h| h == &key_field) else {
                return Ok(HashMap::new());
            };
            let value_index = headers.iter().position(|h| h == &value_field);
            Ok(rows
                .iter()
                .filter_map(|row| {
                    let key = row.get(index)?;
                    if key.is_empty() {
                        return None;
                    }
                    let value = value_index
                        .and_then(|i| row.get(i))
                        .cloned()
                        .unwrap_or_default();
                    Some((key.trim().to_owned(), value))
                })
                .collect())
        })
    })
}

#[pyfunction]
pub fn csv_write(
    py: Python<'_>,
    path: String,
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
    append: bool,
) -> PyResult<()> {
    write_csv(py, path, headers, rows, append, true)
}

#[pyfunction]
pub fn csv_log_append(
    py: Python<'_>,
    path: String,
    headers: Vec<String>,
    row: Vec<String>,
    durable: bool,
) -> PyResult<()> {
    py.allow_threads(|| cached_log_append(&path, &headers, &row, durable))
}

static LOG_FILES: OnceLock<Mutex<HashMap<(u32, PathBuf), Arc<Mutex<File>>>>> = OnceLock::new();
fn open_log(path: &Path) -> PyResult<File> {
    if let Some(parent) = path.parent().filter(|parent| !parent.is_dir()) {
        std::fs::create_dir_all(parent).map_err(error)?;
    }
    OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .open(path)
        .map_err(error)
}
#[cfg(unix)]
fn same_log_target(file: &File, path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (file.metadata(), path.metadata()) {
        (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
        _ => false,
    }
}
#[cfg(windows)]
fn same_log_target(file: &File, path: &Path) -> bool {
    use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetFileInformationByHandle(handle: *mut std::ffi::c_void, info: *mut u32) -> i32;
    }
    fn identity(file: &File) -> Option<(u32, u32, u32, u32, u32)> {
        let mut info = [0u32; 13];
        // BY_HANDLE_FILE_INFORMATION is thirteen DWORDs. Match volume, index and
        // creation time; attribute-only handles avoid reopening file contents.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), info.as_mut_ptr()) } == 0 {
            return None;
        }
        if info[11] == 0 && info[12] == 0 {
            return None;
        }
        Some((info[7], info[11], info[12], info[1], info[2]))
    }
    let target = OpenOptions::new().access_mode(0x80).open(path);
    match target {
        Ok(target) => identity(file).is_some_and(|id| identity(&target) == Some(id)),
        Err(_) => false,
    }
}
#[cfg(not(any(unix, windows)))]
fn same_log_target(_file: &File, _path: &Path) -> bool {
    false
}

fn cached_log_append(
    path: &str,
    headers: &[String],
    row: &[String],
    durable: bool,
) -> PyResult<()> {
    let path = Path::new(path);
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir().map_err(error)?.join(path)
    };
    // PID keys ensure a forked worker opens its own file description / lock owner.
    let key = (std::process::id(), absolute.clone());
    let handles = LOG_FILES.get_or_init(|| Mutex::new(HashMap::new()));
    let handle = {
        let mut files = handles.lock().map_err(error)?;
        if files.len() >= 64 && !files.contains_key(&key) {
            files.clear();
        }
        match files.get(&key) {
            Some(file) => file.clone(),
            None => {
                let file = Arc::new(Mutex::new(open_log(&absolute)?));
                files.insert(key, file.clone());
                file
            }
        }
    };
    let mut file = handle.lock().map_err(error)?;
    if !same_log_target(&file, &absolute) {
        *file = open_log(&absolute)?;
    }
    FileExt::lock_exclusive(&*file).map_err(error)?;
    let result: PyResult<()> = (|| {
        let needs_header = file.metadata().map_err(error)?.len() == 0;
        let mut writer = csv::WriterBuilder::new()
            .terminator(csv::Terminator::CRLF)
            .flexible(true)
            .from_writer(&*file);
        if needs_header {
            writer.write_record(headers).map_err(error)?;
        }
        writer.write_record(row).map_err(error)?;
        writer.flush().map_err(error)?;
        if durable {
            file.sync_data().map_err(error)?;
        }
        Ok(())
    })();
    let unlocked = FileExt::unlock(&*file).map_err(error);
    result?;
    unlocked
}

#[pyfunction]
pub fn csv_log_close(py: Python<'_>, path: Option<String>) -> PyResult<()> {
    py.allow_threads(|| {
        let absolute = path
            .map(|path| {
                let path = PathBuf::from(path);
                if path.is_absolute() {
                    Ok(path)
                } else {
                    std::env::current_dir().map(|dir| dir.join(path))
                }
            })
            .transpose()
            .map_err(error)?;
        if let Some(handles) = LOG_FILES.get() {
            handles.lock().map_err(error)?.retain(|(pid, file), _| {
                *pid != std::process::id() || absolute.as_ref().is_some_and(|path| path != file)
            });
        }
        Ok(())
    })
}

#[pyfunction]
pub fn csv_log_append_uncached(
    py: Python<'_>,
    path: String,
    headers: Vec<String>,
    row: Vec<String>,
    durable: bool,
) -> PyResult<()> {
    py.allow_threads(|| {
        let path = Path::new(&path);
        if let Some(parent) = path.parent().filter(|parent| !parent.is_dir()) {
            std::fs::create_dir_all(parent).map_err(error)?;
        }
        // Logs only append. Avoid opening for read/write, seeking, canonicalizing
        // and invalidating policy snapshots on every access-log line.
        // Windows LockFileEx requires a handle with generic read/write access;
        // an append-only handle cannot take the lock used by fs2.
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(path)
            .map_err(error)?;
        FileExt::lock_exclusive(&file).map_err(error)?;
        let needs_header = file.metadata().map_err(error)?.len() == 0;
        {
            let mut writer = csv::WriterBuilder::new()
                .terminator(csv::Terminator::CRLF)
                .flexible(true)
                .from_writer(&mut file);
            if needs_header {
                writer.write_record(headers).map_err(error)?;
            }
            writer.write_record(row).map_err(error)?;
            writer.flush().map_err(error)?;
        }
        if durable {
            file.sync_data().map_err(error)?;
        }
        // Appending increases length; metadata validation refreshes any reader's
        // cached snapshot on its next access without a separate cache operation.
        Ok(())
    })
}

fn write_csv(
    py: Python<'_>,
    path: String,
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
    append: bool,
    durable: bool,
) -> PyResult<()> {
    py.allow_threads(|| {
        let path = Path::new(&path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(error)?;
        }
        // Do not truncate before acquiring the exclusive lock.
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(error)?;
        FileExt::lock_exclusive(&file).map_err(error)?;
        let needs_header = file.metadata().map_err(error)?.len() == 0 || !append;
        if append {
            file.seek(SeekFrom::End(0)).map_err(error)?;
        } else {
            file.set_len(0).map_err(error)?;
            file.seek(SeekFrom::Start(0)).map_err(error)?;
        }
        {
            let mut writer = csv::WriterBuilder::new()
                .terminator(csv::Terminator::CRLF)
                .flexible(true)
                .from_writer(&mut file);
            if needs_header {
                writer.write_record(&headers).map_err(error)?;
            }
            for row in rows {
                writer.write_record(&row).map_err(error)?;
            }
            writer.flush().map_err(error)?;
        }
        if durable {
            file.sync_data().map_err(error)?;
        }
        let key = path.canonicalize().map_err(error)?;
        cache().lock().map_err(error)?.remove(&key);
        Ok(())
    })
}

#[pyfunction]
pub fn csv_headers_match(py: Python<'_>, path: String, expected: Vec<String>) -> PyResult<bool> {
    py.allow_threads(|| with_table(&path, true, |(headers, _)| Ok(headers == &expected)))
}

#[pyfunction]
pub fn csv_lookup(
    py: Python<'_>,
    path: String,
    key_field: String,
    key: String,
) -> PyResult<Option<HashMap<String, String>>> {
    py.allow_threads(|| {
        with_snapshot(&path, true, |snapshot| {
            let row = indexed_row(snapshot, &key_field, &key).cloned();
            Ok(row.map(|row| snapshot.1 .0.iter().cloned().zip(row).collect()))
        })
    })
}

fn mutate<T>(
    path: &str,
    expected: &[String],
    update: impl FnOnce(&mut Vec<Vec<String>>) -> PyResult<T>,
) -> PyResult<T> {
    let path = Path::new(path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(error)?;
    }
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(error)?;
    FileExt::lock_exclusive(&file).map_err(error)?;
    let has_header = file.metadata().map_err(error)?.len() != 0;
    let (headers, mut rows) = if !has_header {
        (expected.to_vec(), Vec::new())
    } else {
        parse(&file)?
    };
    if headers != expected {
        return Err(error(
            "Unexpected CSV schema; migrate before native mutation",
        ));
    }
    let original = rows.clone();
    let result = update(&mut rows)?;
    if has_header && rows == original {
        return Ok(result);
    }
    file.set_len(0).map_err(error)?;
    file.seek(SeekFrom::Start(0)).map_err(error)?;
    {
        let mut writer = csv::WriterBuilder::new()
            .terminator(csv::Terminator::CRLF)
            .from_writer(&mut file);
        writer.write_record(headers).map_err(error)?;
        for row in rows {
            writer.write_record(row).map_err(error)?;
        }
        writer.flush().map_err(error)?;
    }
    file.sync_data().map_err(error)?;
    cache()
        .lock()
        .map_err(error)?
        .remove(&path.canonicalize().map_err(error)?);
    Ok(result)
}

#[pyfunction]
pub fn csv_blocklist_check(
    py: Python<'_>,
    path: String,
    headers: Vec<String>,
    ip: String,
    now: f64,
) -> PyResult<bool> {
    py.allow_threads(|| {
        let state = with_snapshot(&path, true, |snapshot| {
            Ok(indexed_row(snapshot, "ip", &ip).map(|row| {
                row.get(8)
                    .and_then(|v| v.parse::<f64>().ok())
                    .is_some_and(|expiry| expiry != 0.0 && expiry <= now)
            }))
        })?;
        match state {
            None => Ok(false),
            Some(false) => Ok(true),
            Some(true) => mutate(&path, &headers, |rows| {
                // Recheck under the write lock: another worker may have refreshed
                // this IP after the cached read. Never delete that new block.
                let active = rows
                    .iter()
                    .rev()
                    .find(|row| row.first() == Some(&ip))
                    .is_some_and(|row| {
                        !row.get(8)
                            .and_then(|v| v.parse::<f64>().ok())
                            .is_some_and(|expiry| expiry != 0.0 && expiry <= now)
                    });
                if !active {
                    rows.retain(|row| row.first() != Some(&ip));
                }
                Ok(active)
            }),
        }
    })
}

#[pyfunction]
#[pyo3(signature = (path, headers, ip, reason, added_date, info_json, now, duration))]
#[allow(clippy::too_many_arguments)]
pub fn csv_blocklist_block(
    py: Python<'_>,
    path: String,
    headers: Vec<String>,
    ip: String,
    reason: String,
    added_date: String,
    info_json: Option<String>,
    now: f64,
    duration: Option<i64>,
) -> PyResult<()> {
    py.allow_threads(|| {
        mutate(&path, &headers, |rows| {
            let old = rows.iter().rev().find(|r| r.first() == Some(&ip));
            let old = old.filter(|r| {
                !r.get(8)
                    .and_then(|v| v.parse::<f64>().ok())
                    .is_some_and(|expiry| expiry != 0.0 && expiry <= now)
            });
            let score = old
                .and_then(|r| r.get(5))
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            let offenses = old
                .and_then(|r| r.get(6))
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            let reasons = old
                .and_then(|r| r.get(11))
                .and_then(|v| serde_json::from_str::<Vec<String>>(v).ok())
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| {
                    old.and_then(|r| r.get(1))
                        .map(|r| vec![r.clone()])
                        .unwrap_or_default()
                });
            let info = info_json
                .or_else(|| old.and_then(|r| r.get(4)).cloned())
                .unwrap_or_default();
            let (score, offenses, reasons, _, default_duration) =
                crate::runtime_policy::policy_reputation(score, offenses, reasons, reason.clone());
            let duration = match duration {
                None => Some(default_duration.unwrap_or(900)),
                Some(v) if v <= 0 => None,
                Some(v) => Some(v),
            };
            let reputation = format!("{}; score={score}; offenses={offenses}", reasons.join(", "));
            rows.retain(|r| r.first() != Some(&ip));
            rows.push(vec![
                ip,
                reason,
                reputation,
                added_date,
                info,
                score.to_string(),
                offenses.to_string(),
                now.to_string(),
                duration
                    .map(|d| (now + d as f64).to_string())
                    .unwrap_or_default(),
                duration.map(|d| d.to_string()).unwrap_or_default(),
                if duration.is_none() { "True" } else { "False" }.into(),
                serde_json::to_string(&reasons).map_err(error)?,
            ]);
            Ok(())
        })
    })
}

#[pyfunction]
pub fn csv_remove_key(
    py: Python<'_>,
    path: String,
    headers: Vec<String>,
    key: String,
) -> PyResult<()> {
    py.allow_threads(|| {
        mutate(&path, &headers, |rows| {
            rows.retain(|r| r.first() != Some(&key));
            Ok(())
        })
    })
}

#[pyfunction]
pub fn csv_kv_get(py: Python<'_>, path: String, key: String, now: f64) -> PyResult<Option<String>> {
    py.allow_threads(|| {
        if !Path::new(&path).exists() {
            return Ok(None);
        }
        with_snapshot(&path, true, |snapshot| {
            if snapshot.1 .0 != &["key", "value", "expires_at"] {
                return Err(error("Invalid key/value CSV schema"));
            }
            Ok(indexed_row(snapshot, "key", &key).and_then(|r| {
                let expired = r
                    .get(2)
                    .and_then(|v| v.parse::<f64>().ok())
                    .is_some_and(|expiry| expiry != 0.0 && now > expiry);
                if expired {
                    None
                } else {
                    r.get(1).cloned()
                }
            }))
        })
    })
}

#[pyfunction]
pub fn csv_kv_keys(py: Python<'_>, path: String, now: f64) -> PyResult<Vec<String>> {
    py.allow_threads(|| {
        if !Path::new(&path).exists() {
            return Ok(Vec::new());
        }
        with_table(&path, true, |(headers, rows)| {
            if headers != &["key", "value", "expires_at"] {
                return Err(error("Invalid key/value CSV schema"));
            }
            Ok(rows
                .iter()
                .filter(|r| {
                    !r.get(2)
                        .and_then(|v| v.parse::<f64>().ok())
                        .is_some_and(|expiry| expiry != 0.0 && now > expiry)
                })
                .filter_map(|r| r.first().cloned())
                .collect())
        })
    })
}

#[pyfunction]
#[pyo3(signature = (path, key, value, expires_at, now))]
pub fn csv_kv_update(
    py: Python<'_>,
    path: String,
    key: String,
    value: Option<String>,
    expires_at: Option<f64>,
    now: f64,
) -> PyResult<bool> {
    py.allow_threads(|| {
        let path = Path::new(&path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(error)?;
        }
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(error)?;
        FileExt::lock_exclusive(&file).map_err(error)?;
        let (headers, mut rows) = if file.metadata().map_err(error)?.len() == 0 {
            (
                vec!["key".into(), "value".into(), "expires_at".into()],
                Vec::new(),
            )
        } else {
            parse(&file)?
        };
        if headers != &["key", "value", "expires_at"] {
            return Err(error("Invalid key/value CSV schema"));
        }
        let found = rows.iter().any(|r| r.first() == Some(&key));
        rows.retain(|r| {
            r.first() != Some(&key)
                && !r
                    .get(2)
                    .and_then(|v| v.parse::<f64>().ok())
                    .is_some_and(|expiry| expiry != 0.0 && now > expiry)
        });
        let setting = value.is_some();
        if let Some(value) = value {
            rows.push(vec![
                key,
                value,
                expires_at.map(|v| v.to_string()).unwrap_or_default(),
            ]);
        }
        file.set_len(0).map_err(error)?;
        file.seek(SeekFrom::Start(0)).map_err(error)?;
        {
            let mut writer = csv::WriterBuilder::new()
                .terminator(csv::Terminator::CRLF)
                .from_writer(&mut file);
            writer.write_record(headers).map_err(error)?;
            for row in rows {
                writer.write_record(row).map_err(error)?;
            }
            writer.flush().map_err(error)?;
        }
        file.sync_data().map_err(error)?;
        cache()
            .lock()
            .map_err(error)?
            .remove(&path.canonicalize().map_err(error)?);
        Ok(setting || found)
    })
}

fn kv_headers() -> Vec<String> {
    ["key", "value", "expires_at"].map(str::to_owned).to_vec()
}

#[pyfunction]
pub fn csv_rate_consume(
    py: Python<'_>,
    path: String,
    key: String,
    now: f64,
    window: f64,
    max_requests: i64,
    flood: i64,
) -> PyResult<(String, usize, Vec<f64>)> {
    py.allow_threads(|| {
        mutate(&path, &kv_headers(), |rows| {
            let old = kv_value(rows, &key, now);
            let timestamps = old
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_f64()).collect())
                .unwrap_or_default();
            let decision =
                crate::runtime_policy::policy_rate(timestamps, now, window, max_requests, flood);
            // Expired buckets need not accumulate in a persistent rate cache.
            rows.retain(|r| {
                !r.get(2)
                    .and_then(|v| v.parse::<f64>().ok())
                    .is_some_and(|expiry| expiry != 0.0 && now > expiry)
            });
            kv_put(
                rows,
                key,
                serde_json::json!(decision.2),
                Some(now + window.max(1.0)),
            )?;
            Ok(decision)
        })
    })
}

fn kv_value(rows: &[Vec<String>], key: &str, now: f64) -> serde_json::Value {
    rows.iter()
        .rev()
        .find(|r| r.first().is_some_and(|k| k == key))
        .filter(|r| {
            !r.get(2)
                .and_then(|v| v.parse::<f64>().ok())
                .is_some_and(|expiry| expiry != 0.0 && now > expiry)
        })
        .and_then(|r| r.get(1))
        .map(|raw| {
            serde_json::from_str(raw).unwrap_or_else(|_| serde_json::Value::String(raw.clone()))
        })
        .unwrap_or(serde_json::Value::Null)
}

fn kv_put(
    rows: &mut Vec<Vec<String>>,
    key: String,
    value: serde_json::Value,
    expiry: Option<f64>,
) -> PyResult<()> {
    rows.retain(|r| r.first() != Some(&key));
    rows.push(vec![
        key,
        serde_json::to_string(&value).map_err(error)?,
        expiry.map(|v| v.to_string()).unwrap_or_default(),
    ]);
    Ok(())
}

#[pyfunction]
pub fn csv_runtime_list_update(
    py: Python<'_>,
    path: String,
    operation: String,
    value: String,
    reason: String,
    now: f64,
) -> PyResult<bool> {
    py.allow_threads(|| {
        mutate(&path, &kv_headers(), |rows| {
            let (key, field, remove) = match operation.as_str() {
                "add_ip" => ("exemptions", "ips", false),
                "remove_ip" => ("exemptions", "ips", true),
                "add_pattern" => ("exemptions", "patterns", false),
                "remove_pattern" => ("exemptions", "patterns", true),
                "add_country" => ("geo_blocked_countries", "", false),
                "remove_country" => ("geo_blocked_countries", "", true),
                _ => return Err(error("Unknown policy-list operation")),
            };
            let old = kv_value(rows, key, now);
            let mut data = if key == "exemptions" {
                if old.is_null() {
                    serde_json::json!({"ips":[], "patterns":[]})
                } else if old.is_object() {
                    old
                } else {
                    return Err(error("Invalid exemptions data"));
                }
            } else {
                old
            };
            let raw = if field.is_empty() {
                &data
            } else {
                &data[field]
            };
            let mut list = if raw.is_null() {
                Vec::new()
            } else {
                raw.as_array()
                    .ok_or_else(|| error("Invalid policy list"))?
                    .iter()
                    .map(|v| {
                        v.as_str()
                            .map(str::to_owned)
                            .ok_or_else(|| error("Invalid policy-list value"))
                    })
                    .collect::<PyResult<Vec<_>>>()?
            };
            if key == "geo_blocked_countries" {
                list = list
                    .into_iter()
                    .filter(|v| !v.is_empty())
                    .map(|v| v.trim().to_uppercase())
                    .collect();
            }
            let found = list.contains(&value);
            if remove {
                list.retain(|v| v != &value);
            } else if !found {
                list.push(value.clone());
            }
            if field == "ips" || field.is_empty() {
                list.sort();
                list.dedup();
            }
            if field.is_empty() {
                data = serde_json::json!(list);
            } else {
                data[field] = serde_json::json!(list);
            }
            // Validate the log before writing either key, so a bad log cannot commit
            // a partial exemption change.
            let log = if operation == "add_ip" {
                let old = kv_value(rows, "exemption_log", now);
                let mut log = if old.is_null() {
                    Vec::new()
                } else {
                    old.as_array()
                        .ok_or_else(|| error("Invalid exemption log"))?
                        .clone()
                };
                log.push(serde_json::json!({"ip":value, "reason":reason, "timestamp":now}));
                Some(log)
            } else {
                None
            };
            kv_put(rows, key.into(), data, None)?;
            if let Some(log) = log {
                kv_put(rows, "exemption_log".into(), log.into(), None)?;
            }
            Ok(found)
        })
    })
}

#[pyfunction]
pub fn csv_policy_list_update(
    py: Python<'_>,
    path: String,
    headers: Vec<String>,
    key: String,
    row: Vec<String>,
    remove: bool,
    mode: String,
) -> PyResult<()> {
    if !["exact", "lower", "upper"].contains(&mode.as_str()) {
        return Err(error("Invalid key normalization"));
    }
    let normalize = |value: &str| match mode.as_str() {
        "lower" => value.trim().to_lowercase(),
        "upper" => value.trim().to_uppercase(),
        _ => value.trim().to_owned(),
    };
    let key = normalize(&key);
    py.allow_threads(|| {
        mutate(&path, &headers, |rows| {
            let matches = |r: &Vec<String>| r.first().is_some_and(|v| normalize(v) == key);
            if remove {
                rows.retain(|r| !matches(r));
            } else if !rows.iter().any(matches) {
                if row.len() != headers.len() || row.first().is_none_or(|v| normalize(v) != key) {
                    return Err(error("Invalid policy-list row"));
                }
                rows.push(row);
            }
            Ok(())
        })
    })
}

/// Reputation and the bounded audit log commit under the same cross-worker lock.
#[pyfunction]
#[pyo3(signature = (path, ip, reason, info_json, now, duration))]
pub fn csv_runtime_block(
    py: Python<'_>,
    path: String,
    ip: String,
    reason: String,
    info_json: Option<String>,
    now: f64,
    duration: Option<i64>,
) -> PyResult<()> {
    let info = info_json
        .map(|v| serde_json::from_str::<serde_json::Value>(&v).map_err(error))
        .transpose()?;
    py.allow_threads(|| mutate(&path, &kv_headers(), |rows| {
        let key = format!("blocked:{ip}");
        let old = kv_value(rows, &key, now);
        let score = old.get("score").and_then(|v| v.as_i64()).unwrap_or(if old.is_string() {100} else {0});
        let offenses = old.get("offenses").and_then(|v| v.as_i64()).unwrap_or(if old.is_string() {1} else {0});
        let reasons = if let Some(reason) = old.as_str() {
            vec!["legacy_blacklist".into(), reason.into()]
        } else {
            match old.get("reasons").filter(|v| !v.is_null() && v.as_array().is_none_or(|a| !a.is_empty()))
                .or_else(|| old.get("reason")) {
                Some(serde_json::Value::Array(a)) => a.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect(),
                Some(serde_json::Value::String(s)) => vec![s.clone()],
                _ => Vec::new(),
            }
        };
        let (score, offenses, reasons, _, default_duration) =
            crate::runtime_policy::policy_reputation(score, offenses, reasons, reason.clone());
        let duration = match duration { None => Some(default_duration.unwrap_or(900)),
            Some(d) if d <= 0 => None, Some(d) => Some(d) };
        let expiry = duration.map(|d| now + d as f64);
        let mut data = serde_json::json!({"ip":ip,"reason":reason,
            "reputation_reason":format!("{}; score={score}; offenses={offenses}", reasons.join(", ")),
            "reasons":reasons,"score":score,"offenses":offenses,"blocked_at":now,
            "duration":duration,"expires_at":expiry,"permanent":duration.is_none()});
        if let Some(info) = info { data["extended_request_info"] = info; }
        let mut log = kv_value(rows, "block_log", now).as_array().cloned().unwrap_or_default();
        log.push(data.clone());
        if log.len() > 1000 { log.drain(..log.len()-1000); }
        kv_put(rows, key, data, expiry)?;
        kv_put(rows, "block_log".into(), log.into(), None)
    }))
}

#[pyfunction]
pub fn csv_runtime_keyword(
    py: Python<'_>,
    path: String,
    keyword: String,
    count: i64,
    remove: bool,
    now: f64,
) -> PyResult<()> {
    py.allow_threads(|| {
        mutate(&path, &kv_headers(), |rows| {
            let value = kv_value(rows, "keyword_counts", now);
            let mut counts = value.as_object().cloned().unwrap_or_default();
            if remove {
                counts.remove(&keyword);
            } else {
                let previous = counts
                    .get(&keyword)
                    .and_then(|v| {
                        v.as_i64()
                            .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
                    })
                    .unwrap_or(0);
                let updated = previous
                    .checked_add(count.max(1))
                    .ok_or_else(|| error("Keyword count overflow"))?;
                counts.insert(keyword, updated.into());
            }
            kv_put(rows, "keyword_counts".into(), counts.into(), None)
        })
    })
}

/// Mutate a presence-only CSV without a Python read/modify/write round trip.
#[pyfunction]
pub fn csv_runtime_keywords_update(
    py: Python<'_>,
    path: String,
    added: Vec<(String, i64)>,
    removed: HashSet<String>,
    now: f64,
) -> PyResult<()> {
    py.allow_threads(|| {
        mutate(&path, &kv_headers(), |rows| {
            let value = kv_value(rows, "keyword_counts", now);
            let mut counts = value.as_object().cloned().unwrap_or_default();
            for key in removed {
                counts.remove(&key);
            }
            for (key, count) in added {
                let previous = counts
                    .get(&key)
                    .and_then(|v| {
                        v.as_i64()
                            .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
                    })
                    .unwrap_or(0);
                let updated = previous
                    .checked_add(count.max(1))
                    .ok_or_else(|| error("Keyword count overflow"))?;
                counts.insert(key, updated.into());
            }
            kv_put(rows, "keyword_counts".into(), counts.into(), None)
        })
    })
}

#[pyfunction]
pub fn csv_set_update(
    py: Python<'_>,
    path: String,
    headers: Vec<String>,
    key: String,
    row: Vec<String>,
    remove: bool,
) -> PyResult<()> {
    py.allow_threads(|| {
        mutate(&path, &headers, |rows| {
            if remove {
                rows.retain(|r| r.first() != Some(&key));
            } else if !rows.iter().any(|r| r.first() == Some(&key)) {
                rows.push(row);
            }
            Ok(())
        })
    })
}

/// Evaluate the keyword policy and persist learned keywords in one native call.
#[pyfunction]
#[allow(clippy::too_many_arguments)]
pub fn csv_keyword_apply(
    py: Python<'_>,
    file: String,
    added_date: String,
    path: String,
    query: String,
    query_keys: HashSet<String>,
    exists: bool,
    learning: bool,
    static_kw: HashSet<String>,
    dynamic_kw: HashSet<String>,
    legitimate: HashSet<String>,
    exempt: HashSet<String>,
    prefixes: Vec<String>,
    malicious: HashSet<String>,
) -> PyResult<(Option<String>, Vec<String>, Vec<String>)> {
    let decision = crate::runtime_policy::policy_keyword_flask(
        py, path, query, query_keys, exists, learning, static_kw, dynamic_kw, legitimate, exempt,
        prefixes, malicious,
    );
    if learning && !decision.1.is_empty() {
        py.allow_threads(|| {
            mutate(&file, &["keyword".into(), "added_date".into()], |rows| {
                let mut present: HashSet<String> = rows
                    .iter()
                    .filter_map(|r| r.first())
                    .map(|v| v.trim().to_owned())
                    .collect();
                for keyword in &decision.1 {
                    if present.insert(keyword.clone()) {
                        rows.push(vec![keyword.clone(), added_date.clone()]);
                    }
                }
                Ok(())
            })
        })?;
    }
    Ok(decision)
}

/// Read dynamic keywords, evaluate policy and persist learning at one API boundary.
#[pyfunction]
pub fn csv_keyword_apply_from_store(
    py: Python<'_>,
    file: String,
    added_date: String,
    path: String,
    query: String,
    query_keys: HashSet<String>,
    exists: bool,
    learning: bool,
    static_kw: HashSet<String>,
    legitimate: HashSet<String>,
    exempt: HashSet<String>,
    prefixes: Vec<String>,
    malicious: HashSet<String>,
    top_n: i64,
) -> PyResult<(Option<String>, Vec<String>, Vec<String>)> {
    use pyo3::types::PySet;
    let dynamic = if learning {
        if !Path::new(&file).exists() {
            csv_write(
                py,
                file.clone(),
                vec!["keyword".into(), "added_date".into()],
                Vec::new(),
                true,
            )?;
        }
        let values = csv_read_set(py, file.clone(), "keyword".into(), true)?;
        let raw = PySet::new_bound(py, values.iter())?;
        let copied = py.import_bound("builtins")?.getattr("set")?.call1((raw,))?;
        let copied = copied.downcast::<PySet>()?;
        let count = if top_n < 0 {
            copied
                .len()
                .saturating_sub(usize::try_from(top_n.unsigned_abs()).unwrap_or(usize::MAX))
        } else {
            usize::try_from(top_n).unwrap_or(usize::MAX)
        };
        copied
            .iter()
            .take(count)
            .map(|v| v.extract::<String>())
            .collect::<PyResult<HashSet<_>>>()?
    } else {
        HashSet::new()
    };
    csv_keyword_apply(
        py, file, added_date, path, query, query_keys, exists, learning, static_kw, dynamic,
        legitimate, exempt, prefixes, malicious,
    )
}

/// A training run removes exempt tokens and adds learned tokens in one transaction.
#[pyfunction]
pub fn csv_keywords_update(
    py: Python<'_>,
    path: String,
    added_date: String,
    added: Vec<String>,
    removed: HashSet<String>,
) -> PyResult<()> {
    py.allow_threads(|| {
        mutate(&path, &["keyword".into(), "added_date".into()], |rows| {
            rows.retain(|row| !row.first().is_some_and(|key| removed.contains(key.trim())));
            let mut present: HashSet<String> = rows
                .iter()
                .filter_map(|row| row.first())
                .map(|key| key.trim().to_owned())
                .collect();
            for keyword in added {
                if present.insert(keyword.clone()) {
                    rows.push(vec![keyword, added_date.clone()]);
                }
            }
            Ok(())
        })
    })
}

/// One Python/native boundary for allowlist and path exemption decisions.
#[pyfunction]
pub fn csv_request_exempt(
    py: Python<'_>,
    allowlist: String,
    ip: String,
    path: String,
    rules: Vec<(String, Option<String>)>,
) -> PyResult<Option<bool>> {
    if csv_contains(py, allowlist, "ip".into(), ip, true)? {
        return Ok(Some(true));
    }
    if path.is_empty() {
        return Ok(Some(false));
    }
    Ok(crate::exemption_policy::policy_path_exempt(
        py, path, rules, true,
    ))
}

/// Read dynamic geo state and evaluate the policy in one extension call.
#[pyfunction]
pub fn csv_geo_policy(
    py: Python<'_>,
    file: String,
    country: String,
    allow: HashSet<String>,
    block: HashSet<String>,
) -> PyResult<(bool, String, String)> {
    let dynamic = csv_read_set(py, file, "country".into(), true)?
        .into_iter()
        .map(|value| value.trim().to_uppercase())
        .filter(|value| !value.is_empty())
        .collect();
    Ok(crate::runtime_policy::policy_geo(
        country, allow, block, dynamic,
    ))
}

/// KV-backed geo state used by FastAPI and Django CSV stores. Unsupported
/// legacy values return None so the host retains its existing conversion path.
#[pyfunction]
pub fn csv_runtime_geo_policy(
    py: Python<'_>,
    file: String,
    country: String,
    allow: HashSet<String>,
    block: HashSet<String>,
    extra: HashSet<String>,
    now: f64,
) -> PyResult<Option<(bool, String, String)>> {
    let raw = csv_kv_get(py, file, "geo_blocked_countries".into(), now)?;
    let mut dynamic = extra;
    if let Some(raw) = raw {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw) else {
            return Ok(None);
        };
        if !value.is_null() {
            let Some(values) = value.as_array() else {
                return Ok(None);
            };
            for value in values {
                let Some(value) = value.as_str() else {
                    return Ok(None);
                };
                if !value.is_empty() {
                    dynamic.insert(value.trim().to_uppercase());
                }
            }
        }
    }
    Ok(Some(crate::runtime_policy::policy_geo(
        country, allow, block, dynamic,
    )))
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(csv_runtime_geo_policy, m)?)?;
    m.add_function(wrap_pyfunction!(csv_geo_policy, m)?)?;
    m.add_function(wrap_pyfunction!(csv_runtime_keywords_update, m)?)?;
    m.add_function(wrap_pyfunction!(csv_log_append, m)?)?;
    m.add_function(wrap_pyfunction!(csv_log_close, m)?)?;
    m.add_function(wrap_pyfunction!(csv_log_append_uncached, m)?)?;
    m.add_function(wrap_pyfunction!(csv_keyword_apply, m)?)?;
    m.add_function(wrap_pyfunction!(csv_keyword_apply_from_store, m)?)?;
    m.add_function(wrap_pyfunction!(csv_keywords_update, m)?)?;
    m.add_function(wrap_pyfunction!(csv_runtime_list_update, m)?)?;
    m.add_function(wrap_pyfunction!(csv_policy_list_update, m)?)?;
    m.add_function(wrap_pyfunction!(csv_request_exempt, m)?)?;
    m.add_function(wrap_pyfunction!(csv_rate_consume, m)?)?;
    m.add_function(wrap_pyfunction!(csv_runtime_block, m)?)?;
    m.add_function(wrap_pyfunction!(csv_runtime_keyword, m)?)?;
    m.add_function(wrap_pyfunction!(csv_set_update, m)?)?;
    m.add_function(wrap_pyfunction!(csv_blocklist_check, m)?)?;
    m.add("csv_blacklist_check", m.getattr("csv_blocklist_check")?)?;
    m.add_function(wrap_pyfunction!(csv_read, m)?)?;
    m.add_function(wrap_pyfunction!(csv_read_set, m)?)?;
    m.add_function(wrap_pyfunction!(csv_read_dict, m)?)?;
    m.add_function(wrap_pyfunction!(csv_contains, m)?)?;
    m.add_function(wrap_pyfunction!(csv_write, m)?)?;
    m.add_function(wrap_pyfunction!(csv_headers_match, m)?)?;
    m.add_function(wrap_pyfunction!(csv_lookup, m)?)?;
    m.add_function(wrap_pyfunction!(csv_blocklist_block, m)?)?;
    m.add("csv_blacklist_block", m.getattr("csv_blocklist_block")?)?;
    m.add_function(wrap_pyfunction!(csv_remove_key, m)?)?;
    m.add_function(wrap_pyfunction!(csv_kv_get, m)?)?;
    m.add_function(wrap_pyfunction!(csv_kv_keys, m)?)?;
    m.add_function(wrap_pyfunction!(csv_kv_update, m)?)?;
    Ok(())
}
