const fs = require('fs');
const path = require('path');

function ensureDir(filePath) {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

function escapeCsv(value) {
  const str = String(value ?? '');
  if (str.includes('"') || str.includes(',') || str.includes('\n')) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

function parseCsvLine(line) {
  const cells = [];
  let value = '';
  let quoted = false;
  for (let index = 0; index < String(line).length; index += 1) {
    const char = String(line)[index];
    if (char === '"') {
      if (quoted && String(line)[index + 1] === '"') {
        value += '"';
        index += 1;
      } else {
        quoted = !quoted;
      }
    } else if (char === ',' && !quoted) {
      cells.push(value.trim());
      value = '';
    } else {
      value += char;
    }
  }
  cells.push(value.trim());
  return cells;
}

function readRows(filePath, headers) {
  if (!fs.existsSync(filePath)) return [];

  const raw = fs.readFileSync(filePath, 'utf8').split(/\r?\n/).filter(Boolean);
  if (raw.length === 0) return [];

  const fileHeader = parseCsvLine(raw[0]);
  const hasHeader = fileHeader.some(header => headers.includes(header));
  const sourceHeaders = hasHeader ? fileHeader : headers;
  const startIndex = hasHeader ? 1 : 0;
  const rows = [];

  for (let i = startIndex; i < raw.length; i += 1) {
    const cells = parseCsvLine(raw[i]);
    if (cells.length === 0) continue;
    const row = {};
    headers.forEach(header => {
      const index = sourceHeaders.indexOf(header);
      row[header] = index >= 0 ? (cells[index] ?? '') : '';
    });
    rows.push(row);
  }

  return rows;
}

function writeRows(filePath, headers, rows) {
  ensureDir(filePath);
  const lines = [headers.join(',')];
  for (const row of rows) {
    lines.push(headers.map(header => escapeCsv(row[header] ?? '')).join(','));
  }
  const temp = `${filePath}.${process.pid}.${require('crypto').randomUUID()}.tmp`;
  try {
    fs.writeFileSync(temp, `${lines.join('\n')}\n`, 'utf8');
    fs.renameSync(temp, filePath);
  } finally {
    if (fs.existsSync(temp)) fs.unlinkSync(temp);
  }
}

// All blacklist mutations use this lock and read the current file inside it.
// A crash leaves the lock in place; recovery must first stop the owning writer.
async function updateRows(filePath, headers, update, timeoutMs = 60000) {
  filePath = path.resolve(filePath);
  ensureDir(filePath);
  const lock = `${filePath}.lock`;
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      fs.mkdirSync(lock);
      break;
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
      if (Date.now() >= deadline) throw new Error(`CSV mutation lock timeout: ${lock}`);
      await new Promise(resolve => setTimeout(resolve, 25));
    }
  }
  try {
    const { rows, result } = update(readRows(filePath, headers));
    writeRows(filePath, headers, rows);
    return result;
  } finally {
    fs.rmdirSync(lock);
  }
}

function appendRow(filePath, headers, row) {
  ensureDir(filePath);
  if (!fs.existsSync(filePath)) {
    fs.writeFileSync(filePath, `${headers.join(',')}\n`, 'utf8');
  }
  const line = headers.map(header => escapeCsv(row[header] ?? '')).join(',');
  fs.appendFileSync(filePath, `${line}\n`, 'utf8');
}

function nextId(rows) {
  let max = 0;
  for (const row of rows) {
    const value = Number(row.id || 0);
    if (Number.isFinite(value) && value > max) max = value;
  }
  return max + 1;
}

module.exports = {
  readRows,
  writeRows,
  appendRow,
  updateRows,
  nextId
};
