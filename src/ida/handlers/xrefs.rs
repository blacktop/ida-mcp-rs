//! Cross-reference handlers.

use crate::error::ToolError;
use crate::ida::types::{XRefInfo, XRefListResult};
use idalib::xref::{XRef, XRefQuery};
use idalib::IDB;
use serde_json::{json, Value};
use std::collections::HashSet;

fn to_xref_info(xref: &XRef) -> XRefInfo {
    XRefInfo {
        from: format!("{:#x}", xref.from()),
        to: format!("{:#x}", xref.to()),
        r#type: format!("{:?}", xref.type_()),
        is_code: xref.is_code(),
    }
}

/// Take a bounded `[offset, offset + limit)` window from a linked chain.
///
/// `advance` yields the next link. Skips `offset` items, collects up to
/// `limit`, and reports whether more remain. Traversal is bounded to
/// `offset + limit + 1` steps so a high-frequency target cannot peg the
/// worker thread.
fn take_window<T>(
    first: Option<T>,
    offset: usize,
    limit: usize,
    mut advance: impl FnMut(&T) -> Option<T>,
) -> (Vec<T>, bool) {
    let mut items = Vec::new();
    let mut current = first;
    let mut skipped = 0;
    let mut truncated = false;

    while let Some(item) = current {
        if skipped < offset {
            skipped += 1;
            current = advance(&item);
            continue;
        }
        if items.len() == limit {
            truncated = true;
            break;
        }
        current = advance(&item);
        items.push(item);
    }

    (items, truncated)
}

/// Walk a bounded window of an xref chain into a paginated result.
///
/// `advance` yields the next link (`next_to`/`next_from`). Only the returned
/// window is formatted into `XRefInfo`; skipped links are traversed raw.
fn collect_window<'a>(
    first: Option<XRef<'a>>,
    offset: usize,
    limit: usize,
    advance: impl FnMut(&XRef<'a>) -> Option<XRef<'a>>,
) -> XRefListResult {
    let (window, truncated) = take_window(first, offset, limit, advance);
    let mut xrefs = Vec::with_capacity(window.len());
    for xref in &window {
        xrefs.push(to_xref_info(xref));
    }
    let next_offset = truncated.then(|| offset + xrefs.len());
    XRefListResult {
        xrefs,
        truncated,
        next_offset,
    }
}

pub fn handle_xrefs_to(
    idb: &Option<IDB>,
    addr: u64,
    offset: usize,
    limit: usize,
) -> Result<XRefListResult, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    Ok(collect_window(
        db.first_xref_to(addr, XRefQuery::ALL),
        offset,
        limit,
        |xref| xref.next_to(),
    ))
}

pub fn handle_xrefs_from(
    idb: &Option<IDB>,
    addr: u64,
    offset: usize,
    limit: usize,
) -> Result<XRefListResult, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    Ok(collect_window(
        db.first_xref_from(addr, XRefQuery::ALL),
        offset,
        limit,
        |xref| xref.next_from(),
    ))
}

pub fn handle_xref_matrix(idb: &Option<IDB>, addrs: &[u64]) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let mut xref_map: std::collections::HashMap<u64, HashSet<u64>> =
        std::collections::HashMap::new();

    for &addr in addrs {
        let mut set = HashSet::new();
        let mut current = db.first_xref_from(addr, XRefQuery::ALL);
        while let Some(xref) = current {
            set.insert(xref.to());
            current = xref.next_from();
        }
        xref_map.insert(addr, set);
    }

    let matrix: Vec<Vec<bool>> = addrs
        .iter()
        .map(|from| {
            addrs
                .iter()
                .map(|to| xref_map.get(from).map(|s| s.contains(to)).unwrap_or(false))
                .collect()
        })
        .collect();

    Ok(json!({
        "addrs": addrs.iter().map(|a| format!("{:#x}", a)).collect::<Vec<_>>(),
        "matrix": matrix
    }))
}

#[cfg(test)]
mod tests {
    use crate::ida::handlers::xrefs::take_window;

    /// Window over the chain `0, 1, .., len - 1`.
    fn window_of(len: usize, offset: usize, limit: usize) -> (Vec<usize>, bool) {
        let first = if len > 0 { Some(0) } else { None };
        take_window(first, offset, limit, |&i| {
            let next = i + 1;
            if next < len {
                Some(next)
            } else {
                None
            }
        })
    }

    #[test]
    fn window_within_available_is_not_truncated() {
        let (items, truncated) = window_of(3, 0, 10);
        assert_eq!(items, vec![0, 1, 2]);
        assert!(!truncated);
    }

    #[test]
    fn window_exactly_full_is_not_truncated() {
        // Exactly `limit` items remain after `offset`: full page, nothing beyond.
        let (items, truncated) = window_of(5, 0, 5);
        assert_eq!(items, vec![0, 1, 2, 3, 4]);
        assert!(!truncated);
    }

    #[test]
    fn window_with_more_available_is_truncated() {
        let (items, truncated) = window_of(100, 0, 5);
        assert_eq!(items, vec![0, 1, 2, 3, 4]);
        assert!(truncated);
    }

    #[test]
    fn offset_skips_leading_items() {
        let (items, truncated) = window_of(10, 3, 4);
        assert_eq!(items, vec![3, 4, 5, 6]);
        assert!(truncated);
    }

    #[test]
    fn offset_past_end_yields_empty() {
        let (items, truncated) = window_of(3, 10, 5);
        assert!(items.is_empty());
        assert!(!truncated);
    }

    #[test]
    fn zero_limit_reports_truncation_without_collecting() {
        let (items, truncated) = window_of(3, 0, 0);
        assert!(items.is_empty());
        assert!(truncated);
    }

    #[test]
    fn zero_limit_at_end_is_not_truncated() {
        let (items, truncated) = window_of(3, 3, 0);
        assert!(items.is_empty());
        assert!(!truncated);
    }
}
