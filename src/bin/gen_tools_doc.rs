use ida_mcp::{ToolCategory, ToolInfo, TOOL_REGISTRY};
use std::collections::HashMap;
use std::fmt::Write as _;

fn category_title(cat: ToolCategory) -> &'static str {
    match cat {
        ToolCategory::Core => "Core",
        ToolCategory::Functions => "Functions",
        ToolCategory::Disassembly => "Disassembly",
        ToolCategory::Decompile => "Decompile",
        ToolCategory::Xrefs => "Xrefs",
        ToolCategory::ControlFlow => "Control Flow",
        ToolCategory::Memory => "Memory",
        ToolCategory::Search => "Search",
        ToolCategory::Metadata => "Metadata",
        ToolCategory::Types => "Types",
        ToolCategory::Editing => "Editing",
        ToolCategory::Debug => "Debug",
        ToolCategory::Ui => "UI",
        ToolCategory::Scripting => "Scripting",
    }
}

fn is_headless_unsupported(cat: ToolCategory) -> bool {
    matches!(
        cat,
        ToolCategory::Types | ToolCategory::Editing | ToolCategory::Ui | ToolCategory::Scripting
    )
}

fn all_tools_unsupported(tools: &[&ToolInfo]) -> bool {
    tools
        .iter()
        .all(|tool| tool.short_desc.contains("not supported"))
}

fn main() {
    let mut groups: HashMap<ToolCategory, Vec<&ToolInfo>> = HashMap::new();
    for tool in TOOL_REGISTRY {
        groups.entry(tool.category).or_default().push(tool);
    }
    for tools in groups.values_mut() {
        tools.sort_by_key(|t| t.name);
    }

    let tool_count = TOOL_REGISTRY.len();
    // Baseline is what a default server advertises: every opt-in capability
    // gate must be excluded, not only the debugger one.
    let baseline_tool_count = TOOL_REGISTRY
        .iter()
        .filter(|tool| !tool.requirements.debugger && !tool.requirements.workspace)
        .count();

    let mut out = String::new();
    let _ = writeln!(out, "# Tools\n");
    let _ = writeln!(
        out,
        "> Auto-generated from `src/tool_registry.rs`. Do not edit by hand."
    );
    let _ = writeln!(out, "> Regenerate with: `just tools-doc`.\n");

    let _ = writeln!(out, "## Discovery Workflow\n");
    let _ = writeln!(
        out,
        "- `tools/list` returns {baseline_tool_count} baseline tools by default ({tool_count} registered including opt-in workspace and debugger tools)"
    );
    let _ = writeln!(
        out,
        "- `tool_catalog(query=...)` searches all tools by intent"
    );
    let _ = writeln!(
        out,
        "- `tool_help(name=...)` returns full documentation and schema"
    );
    let _ = writeln!(
        out,
        "- Debugger tools require `--enable-debugger`; `debug_open_module` also requires `--workspace`"
    );
    let _ = writeln!(
        out,
        "- `--workspace` routes several databases by `database_id`; `list_databases` recovers a handle after a lost response or reconnect"
    );
    let _ = writeln!(
        out,
        "- Call `close_idb` when done to release locks; in multi-client servers coordinate before closing (HTTP/SSE requires the close_token from `open_idb` unless the request is in the owning legacy session)"
    );
    let _ = writeln!(out);

    let _ = writeln!(
        out,
        "Note: `open_idb` accepts .i64/.idb or raw binaries (Mach-O/ELF/PE). Raw binaries are"
    );
    let _ = writeln!(
        out,
        "saved as a .i64 alongside the input by default; analysis is off by default and `idb_out` selects another"
    );
    let _ = writeln!(
        out,
        "output path. Existing output databases are reused only when their recorded input SHA-256 matches."
    );
    let _ = writeln!(
        out,
        "Set `rebuild=true` only when the input changed or stale analysis should be overwritten; an"
    );
    let _ = writeln!(
        out,
        "existing database is overwritten only when its hash or recorded path proves provenance. If a sibling .dSYM"
    );
    let _ = writeln!(
        out,
        "exists and no .i64 is present, its DWARF debug info is loaded automatically.\n"
    );

    for &cat in ToolCategory::all() {
        let Some(tools) = groups.get(&cat) else {
            continue;
        };
        if tools.is_empty() {
            continue;
        }
        let _ = writeln!(out, "## {} (`{}`)\n", category_title(cat), cat.as_str());
        let _ = writeln!(out, "{}", cat.description());
        if is_headless_unsupported(cat) && all_tools_unsupported(tools) {
            let _ = writeln!(
                out,
                "Headless unsupported: these tools return NotSupported in headless mode."
            );
        }
        let _ = writeln!(out, "\n| Tool | Description |");
        let _ = writeln!(out, "|------|-------------|");
        for tool in tools {
            let _ = writeln!(out, "| `{}` | {} |", tool.name, tool.short_desc);
        }
        let _ = writeln!(out);
    }

    let _ = writeln!(out, "## Notes\n");
    let _ = writeln!(
        out,
        "- Many tools accept a single value or array (e.g., `\"0x1000\"` or `[\"0x1000\", \"0x2000\"]`)"
    );
    let _ = writeln!(
        out,
        "- String inputs may be comma-separated: `\"0x1000, 0x2000\"`"
    );
    let _ = writeln!(out, "- Addresses accept hex (`0x1000`) or decimal (`4096`)");
    let _ = writeln!(
        out,
        "- Raw binaries default to `<input>.i64`; use `idb_out` for read-only input locations. Existing output is reused only after input SHA-256 verification"
    );
    let _ = writeln!(
        out,
        "- `debug_open_module` always requires `idb_out`, opens a separate workspace database, and resolves macOS cache-backed modules through IDA 9.4's in-process DSC service"
    );

    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        if let Err(err) = std::fs::write(&args[1], out) {
            eprintln!("failed to write {}: {}", args[1], err);
            std::process::exit(1);
        }
    } else {
        print!("{out}");
    }
}
