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
        ToolCategory::Types
            | ToolCategory::Editing
            | ToolCategory::Debug
            | ToolCategory::Ui
            | ToolCategory::Scripting
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

    let mut out = String::new();
    let _ = writeln!(out, "# Tools\n");
    let _ = writeln!(
        out,
        "> Auto-generated from `src/tool_registry.rs`. Do not edit by hand."
    );
    let _ = writeln!(
        out,
        "> Regenerate with: `cargo run --bin gen_tools_doc -- docs/TOOLS.md`.\n"
    );

    let _ = writeln!(out, "## Discovery Workflow\n");
    let _ = writeln!(
        out,
        "- `tools/list` returns the full tool set (currently {tool_count} tools)"
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
        "- Call `close_idb` when done to release locks; in multi-client servers coordinate before closing (HTTP/SSE requires close_token from open_idb)"
    );
    let _ = writeln!(out);

    let _ = writeln!(
        out,
        "Note: `open_idb` accepts .i64/.idb or raw binaries (Mach-O/ELF/PE). Raw binaries are"
    );
    let _ = writeln!(
        out,
        "auto-analyzed and saved as a .i64 alongside the input. If that generated .i64"
    );
    let _ = writeln!(
        out,
        "already exists, it is opened directly instead of rebuilding the raw input. Set rebuild=true"
    );
    let _ = writeln!(
        out,
        "only when the input changed or stale analysis should be overwritten. If a sibling .dSYM"
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
        "- Raw binaries are auto-analyzed on first open; `.i64` is saved alongside the input and reused on later raw-path opens unless `rebuild=true`"
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
