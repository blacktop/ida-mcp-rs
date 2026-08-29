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
    "lumina_apply",
    "declare_type",
    "apply_types",
    "infer_types",
    "declare_stack",
    "delete_stack",
    "dsc_add_dylib",
    "dsc_add_region",
    "analyze_funcs",
    "debug_launch",
    "debug_attach",
    "debug_stop",
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
    debugger_enabled: bool,
    workspace_enabled: bool,
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
            debugger_enabled: false,
            workspace_enabled: false,
        })
    }

    /// "All tools enabled, no filtering active" — safe default for paths
    /// (e.g. tests) that don't construct from CLI input.
    pub fn unrestricted() -> Self {
        Self {
            enabled: tool_registry::all_tools().map(|t| t.name).collect(),
            is_active: false,
            debugger_enabled: false,
            workspace_enabled: false,
        }
    }

    pub fn with_capabilities(
        mut self,
        debugger_requested: bool,
        workspace_enabled: bool,
    ) -> Result<Self, ToolFilterError> {
        self.debugger_enabled =
            debugger_requested && cfg!(all(target_os = "macos", target_arch = "aarch64"));
        self.workspace_enabled = workspace_enabled;
        if self.enabled_count() == 0 {
            return Err(ToolFilterError::EmptyFinalSet);
        }
        Ok(self)
    }

    pub fn is_enabled(&self, name: &str) -> bool {
        self.enabled.contains(name)
            && tool_registry::get_tool(name).is_some_and(|tool| {
                (!tool.requirements.debugger || self.debugger_enabled)
                    && (!tool.requirements.workspace || self.workspace_enabled)
            })
    }

    /// Whether the debugger capability gate is open. Callers use this to
    /// avoid blaming a missing `--enable-debugger` for a tool that the gate
    /// already allows and some other filter rejected.
    pub fn debugger_enabled(&self) -> bool {
        self.debugger_enabled
    }

    pub fn is_active(&self) -> bool {
        self.is_active
    }

    pub fn enabled_count(&self) -> usize {
        self.enabled
            .iter()
            .filter(|name| self.is_enabled(name))
            .count()
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
    use crate::server::tool_filter::{ToolFilter, ToolFilterError, READ_ONLY_DENY_LIST};
    use crate::tool_registry;

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
        assert!(!f.is_enabled("debug_status"));
        // Workspace-gated tools are absent from default mode for the same
        // reason debugger tools are: their capability was never enabled.
        assert!(!f.is_enabled("list_databases"));
        assert_eq!(
            f.enabled_count(),
            tool_registry::all_tools()
                .filter(|tool| !tool.requirements.debugger && !tool.requirements.workspace)
                .count()
        );
    }

    #[test]
    fn debugger_tools_require_explicit_platform_gate() {
        let disabled = ToolFilter::from_inputs(&[], &[], &[], false)
            .unwrap()
            .with_capabilities(false, false)
            .unwrap();
        assert!(!disabled.is_enabled("debug_status"));
        assert!(disabled.is_enabled("open_idb"));

        let requested = ToolFilter::from_inputs(&[], &[], &[], false)
            .unwrap()
            .with_capabilities(true, false)
            .unwrap();
        assert_eq!(
            requested.is_enabled("debug_status"),
            cfg!(all(target_os = "macos", target_arch = "aarch64"))
        );
    }

    #[test]
    fn read_only_removes_debugger_process_control() {
        let filter = ToolFilter::from_inputs(&[], &[], &[], true)
            .expect("read-only filter")
            .with_capabilities(true, false)
            .expect("debugger gate");

        assert!(!filter.is_enabled("debug_launch"));
        assert!(!filter.is_enabled("debug_attach"));
        assert!(!filter.is_enabled("debug_stop"));
        assert_eq!(
            filter.is_enabled("debug_status"),
            cfg!(all(target_os = "macos", target_arch = "aarch64"))
        );
        assert_eq!(
            filter.is_enabled("debug_modules"),
            cfg!(all(target_os = "macos", target_arch = "aarch64"))
        );
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
    fn lumina_tools_follow_read_and_write_categories() {
        let metadata = ToolFilter::from_inputs(&cat("metadata"), &[], &[], false).unwrap();
        assert!(metadata.is_enabled("lumina_lookup"));
        assert!(!metadata.is_enabled("lumina_apply"));

        let editing = ToolFilter::from_inputs(&cat("editing"), &[], &[], false).unwrap();
        assert!(editing.is_enabled("lumina_apply"));
        assert!(!editing.is_enabled("lumina_lookup"));
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
            "lumina_lookup",
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
    fn workspace_only_final_set_requires_workspace_capability() {
        let error = ToolFilter::from_inputs(&[], &cat("debug_open_module"), &[], false)
            .expect("known workspace tool")
            .with_capabilities(true, false)
            .expect_err("workspace-only selection must not start without --workspace");
        assert_eq!(error, ToolFilterError::EmptyFinalSet);

        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            let filter = ToolFilter::from_inputs(&[], &cat("debug_open_module"), &[], false)
                .expect("known workspace tool")
                .with_capabilities(true, true)
                .expect("supported debugger workspace tool");
            assert!(filter.is_enabled("debug_open_module"));
        }
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
