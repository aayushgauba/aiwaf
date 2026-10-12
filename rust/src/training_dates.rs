//! Common Apache/ISO dates. Unsupported forms fall back to Python's full parser.
use pyo3::prelude::*;
type DateParts = (i32, u32, u32, u32, u32, u32, u32, Option<i32>);
fn number(value: &str) -> Option<u32> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}
fn clock(value: &str) -> Option<(u32, u32, u32, u32)> {
    let parts: Vec<_> = value.split(':').collect();
    if parts.len() != 3 {
        return None;
    }
    let (seconds, fraction) = parts[2]
        .split_once('.')
        .or_else(|| parts[2].split_once(','))
        .unwrap_or((parts[2], ""));
    if parts[2].contains(['.', ',']) && fraction.is_empty() {
        return None;
    }
    if !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut micro = fraction.chars().take(6).collect::<String>();
    while micro.len() < 6 {
        micro.push('0');
    }
    Some((
        number(parts[0])?,
        number(parts[1])?,
        number(seconds)?,
        number(&micro)?,
    ))
}
pub fn parts(value: &str, apache: bool) -> Option<DateParts> {
    if !value.is_ascii() {
        return None;
    }
    if apache {
        let stamp = value.split_whitespace().next()?;
        let pieces: Vec<_> = stamp.split('/').collect();
        if pieces.len() == 3 {
            let (year, time) = pieces[2].split_once(':')?;
            if year.len() != 4 || time.contains(['.', ',']) {
                return None;
            }
            let month = [
                "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
            ]
            .iter()
            .position(|m| *m == pieces[1].to_ascii_lowercase())? as u32
                + 1;
            let (h, m, s, us) = clock(time)?;
            if us != 0 {
                return None;
            }
            return Some((
                number(year)? as i32,
                month,
                number(pieces[0])?,
                h,
                m,
                s,
                0,
                None,
            ));
        }
    }
    if value.len() < 19 || value.as_bytes()[4] != b'-' || value.as_bytes()[7] != b'-' {
        return None;
    }
    let (year, month, day) = (
        number(&value[..4])?,
        number(&value[5..7])?,
        number(&value[8..10])?,
    );
    let time = &value[11..];
    let (time, offset) = if let Some(time) = time.strip_suffix('Z') {
        (time, Some(0))
    } else if let Some(i) = time.find(['+', '-']) {
        let zone = &time[i + 1..];
        let z: Vec<_> = zone.split(':').collect();
        if z.len() != 2 || z[0].len() != 2 || z[1].len() != 2 {
            return None;
        }
        let (h, m) = (number(z[0])?, number(z[1])?);
        if h >= 24 || m >= 60 {
            return None;
        }
        let seconds = (h * 3600 + m * 60) as i32 * if time.as_bytes()[i] == b'-' { -1 } else { 1 };
        (&time[..i], Some(seconds))
    } else {
        (time, None)
    };
    if time.len() < 8 || time.as_bytes()[2] != b':' || time.as_bytes()[5] != b':' {
        return None;
    }
    let (h, m, s, us) = clock(time)?;
    Some((year as i32, month, day, h, m, s, us, offset))
}
#[pyfunction]
fn training_date_parts(py: Python<'_>, dates: Vec<String>, apache: bool) -> Vec<Option<DateParts>> {
    py.allow_threads(|| dates.iter().map(|date| parts(date, apache)).collect())
}
pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(training_date_parts, m)?)?;
    Ok(())
}
