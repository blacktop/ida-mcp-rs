//! Server-side tool filtering — controls which tools are advertised on
//! `tools/list` and accepted on `tools/call`.
//!
//! Compose order (locked semantics, see Phase 2a contract):
//!
//! 1. **No include flags** → start from all tools.
//! 2. **Any `--toolsets` or `--tools`** → start empty, add the union of
//!    selected categories and selected individual tools.
//! 3. **`--exclude-tools`** → subtract; always wins over any include.
//! 4. **`--read-only`** → subtract the curated mutating/arbitrary-code
//!    deny-list; lifecycle/discovery tools stay enabled.

use std::collections::HashSet;
use std::str::FromStr;
use thiserror::Error;

use crate::tool_registry::{self, ToolCategory};

/// Tools removed when `--read-only` is set. Lifecycle/discovery
/// (open_idb, close_idb, analysis_status, task_status, recent_operations,
/// tool_catalog, tool_help, idb_meta, open_dsc, load_debug_info) are
/// deliberately preserved so the server stays usable.
pub const READ_ONLY_DENY_LIST: &[&str] = &[
    "run_script",
    "patch",
    "patch_asm",
    "rename",
    "set_comments",
    "declare_type",
    "apply_types",
    "infer_types",
    "declare_stack",
    "delete_stack",
    "dsc_add_dylib",
    "dsc_add_region",
    "analyze_funcs",
];

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ToolFilterError {
    #[error("unknown toolset category: '{0}' (run `tool_catalog` to list categories)")]
    UnknownToolset(String),
    #[error("unknown tool name: '{0}' (run `tool_catalog` to discover tools)")]
    UnknownTool(String),
    #[error(
        "tool filter resolves to an empty set; refusing to start a server with zero tools \
         (review --toolsets / --tools / --exclude-tools / --read-only)"
    )]
    EmptyFinalSet,
}

#[derive(Debug, Clone)]
pub struct ToolFilter {
    enabled: HashSet<&'static str>,
    /// True when *any* user input narrowed the set (used by tool_catalog
    /// to surface the `filtering_active` field).
    is_active: bool,
}

impl ToolFilter {
    /// Construct from raw CLI/env input. Strings are trimmed; empty
    /// entries are ignored. Unknown names error fast.
    pub fn from_inputs(
        toolsets: &[String],
        tools: &[String],
        exclude_tools: &[String],
        read_only: bool,
    ) -> Result<Self, ToolFilterError> {
        let toolsets = clean(toolsets);
        let tools = clean(tools);
        let excludes = clean(exclude_tools);

        let any_input =
            !toolsets.is_empty() || !tools.is_empty() || !excludes.is_empty() || read_only;

        // Step 1/2: build the include base.
        let mut enabled: HashSet<&'static str> = if toolsets.is_empty() && tools.is_empty() {
            tool_registry::all_tools().map(|t| t.name).collect()
        } else {
            HashSet::new()
        };

        for raw in &toolsets {
            let cat = ToolCategory::from_str(raw)
                .map_err(|_| ToolFilterError::UnknownToolset(raw.clone()))?;
            for tool in tool_registry::tools_by_category(cat) {
                enabled.insert(tool.name);
            }
        }

        for raw in &tools {
            let tool = tool_registry::get_tool(raw)
                .ok_or_else(|| ToolFilterError::UnknownTool(raw.clone()))?;
            enabled.insert(tool.name);
        }

        // Step 3: exclude-list wins.
        for raw in &excludes {
            let tool = tool_registry::get_tool(raw)
                .ok_or_else(|| ToolFilterError::UnknownTool(raw.clone()))?;
            enabled.remove(tool.name);
        }

        // Step 4: read-only deny-list (curated; not the annotation flag —
        // see Phase 2a contract for why open_idb/close_idb stay).
        if read_only {
            for name in READ_ONLY_DENY_LIST {
                enabled.remove(name);
            }
        }

        if enabled.is_empty() {
            return Err(ToolFilterError::EmptyFinalSet);
        }

        Ok(Self {
            enabled,
            is_active: any_input,
        })
    }

    /// "All tools enabled, no filtering active" — safe default for paths
    /// (e.g. tests) that don't construct from CLI input.
    pub fn unrestricted() -> Self {
        Self {
            enabled: tool_registry::all_tools().map(|t| t.name).collect(),
            is_active: false,
        }
    }

    pub fn is_enabled(&self, name: &str) -> bool {
        self.enabled.contains(name)
    }

    pub fn is_active(&self) -> bool {
        self.is_active
    }

    pub fn enabled_count(&self) -> usize {
        self.enabled.len()
    }
}

fn clean(input: &[String]) -> Vec<String> {
    input
        .iter()
        .flat_map(|s| s.split(','))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cat(s: &str) -> Vec<String> {
        vec![s.to_string()]
    }

    #[test]
    fn no_inputs_enables_everything_and_is_inactive() {
        let f = ToolFilter::from_inputs(&[], &[], &[], false).unwrap();
        assert!(!f.is_active());
        assert!(f.is_enabled("open_idb"));
        assert!(f.is_enabled("decompile"));
        assert!(f.is_enabled("run_script"));
        assert!(f.is_enabled("patch"));
        assert_eq!(f.enabled_count(), tool_registry::all_tools().count());
    }

    #[test]
    fn toolsets_replace_implicit_default_all() {
        let f = ToolFilter::from_inputs(&cat("disassembly,decompile"), &[], &[], false).unwrap();
        assert!(f.is_active());
        assert!(f.is_enabled("decompile"));
        assert!(f.is_enabled("disasm"));
        // Categories not selected must not leak in.
        assert!(!f.is_enabled("run_script"));
        assert!(!f.is_enabled("open_idb")); // core not selected
    }

    #[test]
    fn tools_add_to_explicit_toolsets() {
        let f = ToolFilter::from_inputs(&cat("decompile"), &cat("open_idb,callees"), &[], false)
            .unwrap();
        assert!(f.is_enabled("decompile")); // from toolset
        assert!(f.is_enabled("open_idb")); // from explicit tool
        assert!(f.is_enabled("callees")); // from explicit tool
        assert!(!f.is_enabled("run_script"));
    }

    #[test]
    fn exclude_tools_wins_over_includes() {
        let f =
            ToolFilter::from_inputs(&cat("core"), &cat("run_script"), &cat("run_script"), false)
                .unwrap();
        // open_idb (core) stays; run_script was added then excluded.
        assert!(f.is_enabled("open_idb"));
        assert!(!f.is_enabled("run_script"));
    }

    #[test]
    fn read_only_strips_mutating_tools() {
        let f = ToolFilter::from_inputs(&[], &[], &[], true).unwrap();
        // Mutating tools gone:
        for name in READ_ONLY_DENY_LIST {
            assert!(!f.is_enabled(name), "read-only must drop {name}");
        }
        // Lifecycle/discovery preserved:
        for name in [
            "open_idb",
            "open_dsc",
            "close_idb",
            "analysis_status",
            "task_status",
            "recent_operations",
            "tool_catalog",
            "tool_help",
            "idb_meta",
            "load_debug_info",
        ] {
            assert!(f.is_enabled(name), "read-only must keep {name}");
        }
    }

    #[test]
    fn unknown_toolset_rejected() {
        let err = ToolFilter::from_inputs(&cat("not_a_real_category"), &[], &[], false)
            .expect_err("must reject unknown category");
        assert_eq!(
            err,
            ToolFilterError::UnknownToolset("not_a_real_category".into())
        );
    }

    #[test]
    fn unknown_tool_rejected() {
        let err = ToolFilter::from_inputs(&[], &cat("nonexistent_tool"), &[], false)
            .expect_err("must reject unknown tool");
        assert_eq!(err, ToolFilterError::UnknownTool("nonexistent_tool".into()));
        let err = ToolFilter::from_inputs(&[], &[], &cat("nonexistent_tool"), false)
            .expect_err("exclude-tools must also reject unknown");
        assert_eq!(err, ToolFilterError::UnknownTool("nonexistent_tool".into()));
    }

    #[test]
    fn empty_final_set_rejected() {
        // Read-only over a single mutating tool collapses to nothing.
        let err = ToolFilter::from_inputs(&[], &cat("run_script"), &[], true)
            .expect_err("empty final set must be rejected");
        assert_eq!(err, ToolFilterError::EmptyFinalSet);

        // Excluding everything we just included also empties the set.
        let err = ToolFilter::from_inputs(
            &cat("decompile"),
            &[],
            &cat("decompile,pseudocode_at"),
            false,
        )
        .expect_err("exclude wiping all includes must reject");
        assert_eq!(err, ToolFilterError::EmptyFinalSet);
    }

    #[test]
    fn comma_separated_inputs_split_correctly() {
        // Single shell-quoted CSV string should split same as multiple flag uses.
        let f = ToolFilter::from_inputs(
            &cat("disassembly , decompile"),
            &cat(" open_idb , callees "),
            &[],
            false,
        )
        .unwrap();
        assert!(f.is_enabled("decompile"));
        assert!(f.is_enabled("disasm"));
        assert!(f.is_enabled("open_idb"));
        assert!(f.is_enabled("callees"));
    }
}
