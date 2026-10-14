// WASM owns receipt identity and decisions; Node owns durable filesystem I/O.
const fs = require('fs');
const path = require('path');
const { createTrainingEvidence } = require('./wasmAdapter');

async function acquire(directory, timeoutMs = 60000) {
  fs.mkdirSync(directory, { recursive: true });
  const lock = path.join(directory, 'node_training_evidence.lock');
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try { fs.mkdirSync(lock); break; } catch (error) {
      if (error.code !== 'EEXIST') throw error;
      if (Date.now() >= deadline) throw new Error(`Training evidence is locked: ${lock}. If a trainer crashed, confirm it has stopped before removing this lock directory.`);
      await new Promise(resolve => setTimeout(resolve, 100));
    }
  }
  return () => fs.rmdirSync(lock);
}

function persist(file, state) {
  const temporary = `${file}.tmp`;
  const fd = fs.openSync(temporary, 'w');
  try { fs.writeFileSync(fd, state); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  fs.renameSync(temporary, file);
  if (process.platform !== 'win32') {
    const directory = fs.openSync(path.dirname(file), 'r');
    try { fs.fsyncSync(directory); } finally { fs.closeSync(directory); }
  }
}

async function withTrainingEvidence(directory, action, timeoutMs) {
  const release = await acquire(path.resolve(directory), timeoutMs);
  let native;
  try {
    const file = path.join(path.resolve(directory), 'node_training_evidence.json');
    let state;
    try { state = fs.readFileSync(file, 'utf8'); } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      state = '{"version":1,"ips":{}}';
    }
    native = await createTrainingEvidence(state);
    return await action({
      fresh(records) {
        const fields = records.map(row => [row.ip, row.timestamp.toISOString(), row.path, String(row.status)]);
        return JSON.parse(native.fresh_indices(JSON.stringify(fields))).map(index => records[index]);
      },
      async block(ip, perform) {
        if (!native.can_block(ip) || await perform() === false) return false;
        persist(file, native.committed_state(ip));
        native.commit(ip);
        return true;
      }
    });
  } finally {
    try { if (native) native.free(); } finally { release(); }
  }
}

module.exports = { withTrainingEvidence };
