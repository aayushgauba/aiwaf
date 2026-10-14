//! Non-expiring receipts for offline enforcement, independent of block expiry.
use aiwaf_core::training_evidence::ReceiptLedger;
use fs2::FileExt;
use pyo3::{exceptions::PyIOError, prelude::*};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::PathBuf,
    time::{Duration, Instant},
};

#[pyclass]
pub struct TrainingEvidence {
    path: PathBuf,
    lock: Option<File>,
    inner: ReceiptLedger,
}

fn error(e: impl std::fmt::Display) -> PyErr {
    PyIOError::new_err(e.to_string())
}

impl TrainingEvidence {
    fn open(directory: String) -> PyResult<Self> {
        let root = PathBuf::from(directory);
        std::fs::create_dir_all(&root).map_err(error)?;
        let path = root.join("training_evidence.json");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(root.join("training_evidence.lock"))
            .map_err(error)?;
        let start = Instant::now();
        loop {
            match lock.try_lock_exclusive() {
                Ok(()) => break,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.raw_os_error() == fs2::lock_contended_error().raw_os_error() =>
                {
                    if start.elapsed() >= Duration::from_secs(60) {
                        return Err(error("Another AIWAF trainer holds the evidence lock"));
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(e) => return Err(error(e)),
            }
        }
        let json = match std::fs::read_to_string(&path) {
            Ok(json) => json,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                r#"{"version":1,"ips":{}}"#.into()
            }
            Err(e) => return Err(error(e)),
        };
        let inner = ReceiptLedger::from_json(&json).map_err(error)?;
        Ok(Self {
            path,
            lock: Some(lock),
            inner,
        })
    }

    fn observe(&mut self, records: Vec<(String, String, String, String)>) -> PyResult<Vec<usize>> {
        if self.lock.is_none() {
            return Err(error("Training evidence is closed"));
        }
        self.inner.observe(records).map_err(error)
    }

    fn persist(&mut self, ip: String) -> PyResult<()> {
        if !self.allowed(&ip) {
            return Err(error("No fresh training evidence for this IP"));
        }
        let next = self.inner.committed_state(&ip).map_err(error)?;
        let temporary = self.path.with_extension("tmp");
        {
            let mut file = File::create(&temporary).map_err(error)?;
            file.write_all(next.as_bytes()).map_err(error)?;
            file.flush().map_err(error)?;
            file.sync_all().map_err(error)?;
        }
        std::fs::rename(&temporary, &self.path).map_err(error)?;
        #[cfg(unix)]
        File::open(self.path.parent().unwrap())
            .and_then(|f| f.sync_all())
            .map_err(error)?;
        self.inner.commit(&ip).map_err(error)?;
        Ok(())
    }

    fn allowed(&self, ip: &str) -> bool {
        self.lock.is_some() && self.inner.can_block(ip)
    }
}

#[pymethods]
impl TrainingEvidence {
    #[new]
    fn new(py: Python<'_>, directory: String) -> PyResult<Self> {
        py.allow_threads(|| Self::open(directory))
    }
    #[getter]
    fn had_history(&self) -> bool {
        self.inner.had_history
    }
    fn fresh_indices(
        &mut self,
        py: Python<'_>,
        records: Vec<(String, String, String, String)>,
    ) -> PyResult<Vec<usize>> {
        py.allow_threads(|| self.observe(records))
    }
    fn can_block(&self, ip: &str) -> bool {
        self.allowed(ip)
    }
    fn commit(&mut self, py: Python<'_>, ip: String) -> PyResult<()> {
        py.allow_threads(|| self.persist(ip))
    }
    fn close(&mut self) {
        self.lock.take();
    }
}
