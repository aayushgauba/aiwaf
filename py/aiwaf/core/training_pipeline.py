"""Batch native preparation with compatible Python dates and route callbacks."""
from collections import defaultdict
import csv
from datetime import datetime, timedelta, timezone
from io import StringIO

from .native_runtime import function
from .logs import parse_log_line
from itertools import islice
import locale
import os


def convert_training_fields(fields, apache=False, dates=None, legacy_csv=False, prefer_native_iso=False):
    dates = {} if dates is None else dates
    stamps = list(dict.fromkeys(field[1] for field in fields if field[1] not in dates))
    date_native = function('training_date_parts')
    language = locale.getlocale(locale.LC_TIME)[0]
    prefer_native_iso = prefer_native_iso or os.environ.get('AIWAF_RUST_ISO_DATES', '').lower() in {'1', 'true', 'yes', 'on'}
    use_dates = date_native and (not apache or not language or language.lower().startswith('en'))
    native_stamps = [stamp for stamp in stamps if prefer_native_iso or (apache and '/' in stamp)]
    parts = dict(zip(native_stamps, date_native(native_stamps, apache))) if use_dates and native_stamps else {}
    parsed = []
    for ip, stamp, path, status, elapsed in fields:
        if stamp not in dates:
            date = None
            try:
                native_parts = parts.get(stamp)
                if native_parts:
                    offset = native_parts[7]
                    tz = timezone(timedelta(seconds=offset)) if offset is not None else None
                    date = datetime(*native_parts[:7], tzinfo=tz)
                elif apache:
                    try:
                        date = datetime.strptime(stamp.split()[0], '%d/%b/%Y:%H:%M:%S')
                    except (ValueError, IndexError):
                        date = datetime.fromisoformat(stamp.replace('Z', '+00:00'))
                else:
                    try:
                        date = datetime.fromisoformat(stamp.replace('Z', '+00:00'))
                    except ValueError:
                        date = datetime.strptime(stamp.split()[0], '%d/%b/%Y:%H:%M:%S')
            except (ValueError, IndexError):
                pass
            if len(dates) >= 8192:
                dates.clear()
            dates[stamp] = date
        date = dates[stamp]
        if date is not None:
            # Django's previous CSV -> Apache conversion discarded zone/microseconds.
            if legacy_csv:
                date = date.replace(tzinfo=None, microsecond=0)
            parsed.append(dict(ip=ip, timestamp=date, path=path, status=status, response_time=elapsed))
    return parsed


def iter_csv_training_batches(path, batch_size=4096, legacy_csv=False):
    native = function('TrainingCSVReader')
    dates = {}
    if native:
        reader = native(str(path))
        while True:
            count, fields = reader.next_batch(batch_size)
            if not count:
                break
            yield count, convert_training_fields(fields, dates=dates, legacy_csv=legacy_csv)
        return
    import gzip
    opener = gzip.open if str(path).endswith('.gz') else open
    with opener(path, 'rt', encoding='utf-8', newline='') as file:
        reader = csv.DictReader(file)
        while rows := list(islice(reader, batch_size)):
            fields = []
            for row in rows:
                try:
                    elapsed = float(row.get('response_time_ms', row.get('response_time', '0')))
                    if 'response_time_ms' in row:
                        elapsed /= 1000.0
                    fields.append((row['ip'], row['timestamp'], row['path'], row['status_code'], elapsed))
                except (KeyError, ValueError, TypeError):
                    continue
            yield len(rows), convert_training_fields(fields, dates=dates, legacy_csv=legacy_csv)


def iter_training_batches(lines, parse_line=parse_log_line, batch_size=4096, native=True):
    """Keep streaming callers bounded; customized parsers retain their behavior."""
    iterator = iter(lines)
    while batch := list(islice(iterator, max(1, batch_size))):
        records = (parse_training_logs(batch) if native else
                   [record for line in batch if (record := parse_line(line))])
        yield len(batch), records


def count_training_keywords(records, exists, exempt, static_kw, legitimate):
    native = function('training_keyword_counts')
    if not native or any(not r['path'].isascii() for r in records):
        return None
    paths = dict.fromkeys(r['path'] for r in records)
    return native([(r['path'], r['status']) for r in records],
                  {p for p in paths if exists(p)}, {p for p in paths if exempt(p)},
                  set(static_kw), set(legitimate))


def parse_training_logs(lines, parse_line=parse_log_line):
    """Parse real CSV access logs directly, or batch Apache-style extraction."""
    is_csv = bool(lines and {'timestamp', 'ip', 'path', 'status_code'} <=
                  set(next(csv.reader([lines[0]]), [])))
    native = function('training_parse_csv' if is_csv else 'training_parse_lines')
    dates = {}

    parsed = []
    if is_csv:
        if native:
            fields = native(''.join(lines))
        else:
            fields = []
            for row in csv.DictReader(StringIO(''.join(lines))):
                try:
                    fields.append((row['ip'], row['timestamp'], row['path'], row['status_code'],
                                   float(row.get('response_time_ms', '0')) / 1000))
                except (KeyError, TypeError, ValueError):
                    continue
        return convert_training_fields(fields, dates=dates)

    for offset in range(0, len(lines), 4096):
        batch = lines[offset:offset + 4096]
        if native:
            extracted = native(batch)
            # Parse dates once for the complete batch; preserve regex fallback order.
            unique_fields = {field[1]: field for candidates in extracted for field in candidates
                             if field[1] not in dates}
            convert_training_fields(list(unique_fields.values()), apache=True, dates=dates)
            for line, candidates in zip(batch, extracted):
                # Python handles Unicode regex semantics and uncommon numeric forms.
                if not line.isascii():
                    record = parse_line(line)
                else:
                    record = next((dict(ip=f[0], timestamp=dates[f[1]], path=f[2], status=f[3], response_time=f[4])
                                   for f in candidates if dates.get(f[1]) is not None), None)
                if record:
                    parsed.append(record)
        else:
            parsed.extend(record for line in batch if (record := parse_line(line)))
    return parsed


def aggregate_training_records(parsed, path_exempt):
    """Evaluate each distinct 404 path once, then count in a single native call."""
    exempt = {path for path in dict.fromkeys(r['path'] for r in parsed if r['status'] == '404')
              if path_exempt(path)}
    native = function('training_aggregate')
    if native:
        errors, exempt_errors, indices = native(
            [(r['ip'], r['path'], r['status']) for r in parsed], exempt)
        times = {ip: [parsed[i]['timestamp'] for i in ids] for ip, ids in indices.items()}
        return errors, exempt_errors, times
    errors, exempt_errors, times = defaultdict(int), defaultdict(int), defaultdict(list)
    for record in parsed:
        ip = record['ip']
        times[ip].append(record['timestamp'])
        if record['status'] == '404':
            target = exempt_errors if record['path'] in exempt else errors
            target[ip] += 1
    return errors, exempt_errors, times


def learn_training_keywords(parsed, exists, exempt, static_kw, legitimate, top_n):
    native = function('training_keywords')
    if not native or any(not r['path'].isascii() for r in parsed):
        return None
    paths = dict.fromkeys(r['path'] for r in parsed)
    known = {path for path in paths if exists(path)}
    exempt_paths = {path for path in paths if exempt(path)}
    return native([(r['path'], r['status']) for r in parsed], known, exempt_paths,
                  set(static_kw), set(legitimate), top_n)


def anomaly_statistics(features, predictions):
    native = function('training_anomaly_stats')
    if native:
        return native([(r['ip'], float(r['kw_hits']), float(r['total_404']), float(r['burst_count']))
                       for r in features], list(predictions))
    if len(features) != len(predictions):
        raise ValueError('Prediction count mismatch')
    selected = {r['ip'] for r, prediction in zip(features, predictions) if prediction == -1}
    groups = defaultdict(list)
    for record in features:
        if record['ip'] in selected:
            groups[record['ip']].append(record)
    def mean(rows, key):
        values = [float(r[key]) for r in rows if float(r[key]) == float(r[key])]
        return sum(values) / len(values) if values else float('nan')
    return {ip: (mean(rows, 'kw_hits'),
                 max((float(r['total_404']) for r in rows if float(r['total_404']) == float(r['total_404'])), default=float('nan')),
                 mean(rows, 'burst_count'), len(rows)) for ip, rows in groups.items()}


def python_training_features(parsed, errors, times, exists, exempt, static_kw, statuses):
    """Explicit pure-Python fallback for adapters with native processing disabled."""
    features = []
    for record in parsed:
        path, ip = record['path'], record['ip']
        eligible = not exists(path) and not exempt(path)
        features.append(dict(ip=ip, path_len=len(path),
            kw_hits=sum(kw in path.lower() for kw in static_kw) if eligible else 0,
            resp_time=record['response_time'], status_idx=statuses.index(record['status']) if record['status'] in statuses else -1,
            burst_count=sum((record['timestamp'] - stamp).total_seconds() <= 10 for stamp in times.get(ip, [])),
            total_404=errors.get(ip, 0)))
    return features
