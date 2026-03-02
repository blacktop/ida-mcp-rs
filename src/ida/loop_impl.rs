//! Main IDA worker loop.

use std::fs::File;
use std::path::PathBuf;
use std::sync::mpsc;

use idalib::IDB;
use tracing::{debug, error, info, warn};

use crate::error::ToolError;
use crate::ida::handlers::resolve_address;
use crate::ida::handlers::{
    address, analysis, annotations, controlflow, database, disasm, functions, globals, imports,
    memory, script, search, segments, strings, structs, types, xrefs,
};
use crate::ida::lock::release_mcp_lock;
use crate::ida::request::IdaRequest;

/// Log result with debug on success and warn on error.
macro_rules! log_result {
    ($result:expr, $ok_msg:literal, $err_msg:literal) => {
        match &$result {
            Ok(_) => debug!($ok_msg),
            Err(e) => warn!(error = %e, $err_msg),
        }
    };
}

/// Run the IDA worker loop on the current (main) thread.
/// This function blocks until Shutdown is received.
///
/// IDA library initialization is deferred until the first request
/// that needs it. This allows `open_dsc` to run `idat` without
/// license contention (idat needs its own license).
pub fn run_ida_loop(rx: mpsc::Receiver<IdaRequest>) {
    let mut idb: Option<IDB> = None;
    let mut lock_file: Option<File> = None;
    let mut lock_path: Option<PathBuf> = None;
    let mut lib_initialized = false;

    let mut version_mismatch: Option<String> = None;

    while let Ok(req) = rx.recv() {
        // Lazily initialize the IDA library on first use.
        // Must happen on the main thread (which this loop runs on).
        if !lib_initialized {
            info!("Initializing IDA library on main thread (deferred)");
            idalib::init_library();
            lib_initialized = true;

            // Check runtime IDA version against the SDK we compiled with.
            // A mismatch causes segfaults in complex APIs (struct layout
            // differences), so we refuse to proceed.
            let (sdk_major, sdk_minor) = idalib::SDK_VERSION;
            match idalib::version() {
                Ok(v) => {
                    info!("IDA runtime version: {v}");
                    if v.major() != sdk_major || v.minor() != sdk_minor {
                        let msg = format!(
                            "IDA SDK version mismatch: ida-mcp was compiled \
                             for IDA {sdk_major}.{sdk_minor} but the runtime \
                             IDA library is {v}. Install the matching IDA \
                             version or use the ida-mcp release built for \
                             your IDA version.",
                        );
                        error!("{msg}");
                        version_mismatch = Some(msg);
                    }
                }
                Err(e) => {
                    warn!("Could not query IDA runtime version: {e}");
                }
            }
        }

        // If there is a version mismatch, reject every request with a
        // clear error instead of segfaulting deep inside IDA.
        if let Some(ref mismatch_msg) = version_mismatch {
            match req {
                IdaRequest::Shutdown => {
                    info!("Worker shutting down after SDK version mismatch");
                    shutdown_cleanup(&mut idb, &mut lock_file, &mut lock_path);
                    break;
                }
                other => {
                    reject_with_version_error(other, mismatch_msg);
                    continue;
                }
            }
        }
        match req {
            IdaRequest::Open {
                path,
                load_debug_info,
                debug_info_path,
                debug_info_verbose,
                force,
                file_type,
                auto_analyse,
                extra_args,
                resp,
            } => {
                info!(path = %path, force, file_type = ?file_type, auto_analyse, "Opening database");
                let result = database::handle_open(
                    &mut idb,
                    &mut lock_file,
                    &mut lock_path,
                    &path,
                    load_debug_info,
                    debug_info_path.as_deref(),
                    debug_info_verbose,
                    force,
                    file_type.as_deref(),
                    auto_analyse,
                    &extra_args,
                );
                match &result {
                    Ok(info) => info!(
                        path = %info.path,
                        processor = %info.processor,
                        bits = info.bits,
                        functions = info.function_count,
                        "Database opened"
                    ),
                    Err(e) => error!(path = %path, error = %e, "Failed to open database"),
                }
                let _ = resp.send(result);
            }
            IdaRequest::Close { resp } => {
                info!("Closing database");
                if let Some(ref db) = idb {
                    info!(path = %db.path().display(), "Dropping IDB (will call close_database_with(save))");
                }
                drop(idb.take());
                info!("IDB dropped, database should be packed");
                release_mcp_lock(&mut lock_file, &mut lock_path);
                let _ = resp.send(());
            }
            IdaRequest::LoadDebugInfo {
                path,
                verbose,
                resp,
            } => {
                debug!(path = ?path, verbose, "Loading debug info");
                let result = database::handle_load_debug_info(&idb, path.as_deref(), verbose);
                match &result {
                    Ok(v) => debug!(result = %v, "Loaded debug info"),
                    Err(e) => warn!(error = %e, "Failed to load debug info"),
                }
                let _ = resp.send(result);
            }
            IdaRequest::AnalysisStatus { resp } => {
                debug!("Reporting analysis status");
                let result = analysis::handle_analysis_status(&idb);
                match &result {
                    Ok(status) => debug!(
                        auto_enabled = status.auto_enabled,
                        auto_is_ok = status.auto_is_ok,
                        auto_state = %status.auto_state,
                        "Analysis status reported"
                    ),
                    Err(e) => warn!(error = %e, "Failed to report analysis status"),
                }
                let _ = resp.send(result);
            }
            IdaRequest::ListFunctions {
                offset,
                limit,
                filter,
                resp,
            } => {
                debug!(offset, limit, filter = ?filter, "Listing functions");
                let result =
                    functions::handle_list_functions(&idb, offset, limit, filter.as_deref());
                match &result {
                    Ok(r) => debug!(
                        count = r.functions.len(),
                        total = r.total,
                        "Listed functions"
                    ),
                    Err(e) => warn!(error = %e, "Failed to list functions"),
                }
                let _ = resp.send(result);
            }
            IdaRequest::ResolveFunction { name, resp } => {
                debug!(name = %name, "Resolving function");
                let result = functions::handle_resolve_function(&idb, &name);
                match &result {
                    Ok(info) => {
                        debug!(name = %info.name, address = %info.address, "Resolved function")
                    }
                    Err(e) => warn!(name = %name, error = %e, "Failed to resolve function"),
                }
                let _ = resp.send(result);
            }
            IdaRequest::DisasmByName { name, count, resp } => {
                debug!(name = %name, count, "Disassembling by name");
                let result = disasm::handle_disasm_by_name(&idb, &name, count);
                match &result {
                    Ok(text) => {
                        debug!(name = %name, lines = text.lines().count(), "Disassembly complete")
                    }
                    Err(e) => warn!(name = %name, error = %e, "Failed to disassemble"),
                }
                let _ = resp.send(result);
            }
            IdaRequest::Disasm { addr, count, resp } => {
                debug!(address = format!("{:#x}", addr), count, "Disassembling");
                let result = disasm::handle_disasm(&idb, addr, count);
                match &result {
                    Ok(text) => debug!(lines = text.lines().count(), "Disassembly complete"),
                    Err(e) => {
                        warn!(address = format!("{:#x}", addr), error = %e, "Failed to disassemble")
                    }
                }
                let _ = resp.send(result);
            }
            IdaRequest::Decompile { addr, resp } => {
                debug!(address = format!("{:#x}", addr), "Decompiling");
                let result = disasm::handle_decompile(&idb, addr);
                match &result {
                    Ok(code) => debug!(lines = code.lines().count(), "Decompilation complete"),
                    Err(e) => {
                        warn!(address = format!("{:#x}", addr), error = %e, "Failed to decompile")
                    }
                }
                let _ = resp.send(result);
            }
            IdaRequest::Segments { resp } => {
                debug!("Listing segments");
                let result = segments::handle_segments(&idb);
                match &result {
                    Ok(segs) => debug!(count = segs.len(), "Listed segments"),
                    Err(e) => warn!(error = %e, "Failed to list segments"),
                }
                let _ = resp.send(result);
            }
            IdaRequest::Strings {
                offset,
                limit,
                filter,
                resp,
            } => {
                debug!(offset, limit, filter = ?filter, "Listing strings");
                let result = strings::handle_strings(&idb, offset, limit, filter.as_deref());
                match &result {
                    Ok(r) => debug!(count = r.strings.len(), total = r.total, "Listed strings"),
                    Err(e) => warn!(error = %e, "Failed to list strings"),
                }
                let _ = resp.send(result);
            }
            IdaRequest::LocalTypes {
                offset,
                limit,
                filter,
                resp,
            } => {
                debug!(offset, limit, filter = ?filter, "Listing local types");
                let result = types::handle_local_types(&idb, offset, limit, filter.as_deref());
                match &result {
                    Ok(r) => debug!(count = r.types.len(), total = r.total, "Listed local types"),
                    Err(e) => warn!(error = %e, "Failed to list local types"),
                }
                let _ = resp.send(result);
            }
            IdaRequest::DeclareType {
                decl,
                relaxed,
                replace,
                multi,
                resp,
            } => {
                debug!(relaxed, replace, multi, "Declaring type");
                let result = types::handle_declare_type(&idb, &decl, relaxed, replace, multi);
                log_result!(result, "Declared type", "Failed to declare type");
                let _ = resp.send(result);
            }
            IdaRequest::ApplyTypes {
                addr,
                name,
                offset,
                stack_offset,
                stack_name,
                decl,
                type_name,
                relaxed,
                delay,
                strict,
                resp,
            } => {
                debug!(
                    address = ?addr,
                    name = ?name,
                    offset,
                    stack_offset = ?stack_offset,
                    stack_name = ?stack_name,
                    relaxed,
                    delay,
                    strict,
                    "Applying type"
                );
                let result = types::handle_apply_types(
                    &idb,
                    addr,
                    name.as_deref(),
                    offset,
                    stack_offset,
                    stack_name.as_deref(),
                    decl.as_deref(),
                    type_name.as_deref(),
                    relaxed,
                    delay,
                    strict,
                );
                log_result!(result, "Applied type", "Failed to apply type");
                let _ = resp.send(result);
            }
            IdaRequest::InferTypes {
                addr,
                name,
                offset,
                resp,
            } => {
                debug!(address = ?addr, name = ?name, offset, "Inferring type");
                let result = types::handle_infer_types(&idb, addr, name.as_deref(), offset);
                match &result {
                    Ok(res) => debug!(code = res.code, "Inferred type"),
                    Err(e) => warn!(error = %e, "Failed to infer type"),
                }
                let _ = resp.send(result);
            }
            IdaRequest::AddrInfo {
                addr,
                name,
                offset,
                resp,
            } => {
                debug!(address = ?addr, name = ?name, offset, "Getting address info");
                let resolved = resolve_address(&idb, addr, name.as_deref(), offset);
                let result = resolved.and_then(|ea| address::handle_addr_info(&idb, ea));
                log_result!(result, "Got address info", "Failed to get address info");
                let _ = resp.send(result);
            }
            IdaRequest::FunctionAt {
                addr,
                name,
                offset,
                resp,
            } => {
                debug!(address = ?addr, name = ?name, offset, "Getting function at address");
                let resolved = resolve_address(&idb, addr, name.as_deref(), offset);
                let result = resolved.and_then(|ea| functions::handle_function_at(&idb, ea));
                log_result!(
                    result,
                    "Got function at address",
                    "Failed to get function at address"
                );
                let _ = resp.send(result);
            }
            IdaRequest::DisasmFunctionAt {
                addr,
                name,
                offset,
                count,
                resp,
            } => {
                debug!(
                    address = ?addr,
                    name = ?name,
                    offset,
                    count,
                    "Disassembling function at address"
                );
                let resolved = resolve_address(&idb, addr, name.as_deref(), offset);
                let result =
                    resolved.and_then(|ea| disasm::handle_disasm_function_at(&idb, ea, count));
                log_result!(
                    result,
                    "Disassembled function",
                    "Failed to disassemble function"
                );
                let _ = resp.send(result);
            }
            IdaRequest::DeclareStack {
                addr,
                name,
                offset,
                var_name,
                decl,
                relaxed,
                resp,
            } => {
                debug!(
                    address = ?addr,
                    name = ?name,
                    offset,
                    var_name = ?var_name,
                    relaxed,
                    "Declaring stack variable"
                );
                let result = types::handle_declare_stack(
                    &idb,
                    addr,
                    name.as_deref(),
                    offset,
                    var_name.as_deref(),
                    &decl,
                    relaxed,
                );
                match &result {
                    Ok(res) => debug!(code = res.code, "Declared stack variable"),
                    Err(e) => warn!(error = %e, "Failed to declare stack variable"),
                }
                let _ = resp.send(result);
            }
            IdaRequest::DeleteStack {
                addr,
                name,
                offset,
                var_name,
                resp,
            } => {
                debug!(
                    address = ?addr,
                    name = ?name,
                    offset = ?offset,
                    var_name = ?var_name,
                    "Deleting stack variable"
                );
                let result = types::handle_delete_stack(
                    &idb,
                    addr,
                    name.as_deref(),
                    offset,
                    var_name.as_deref(),
                );
                match &result {
                    Ok(res) => debug!(code = res.code, "Deleted stack variable"),
                    Err(e) => warn!(error = %e, "Failed to delete stack variable"),
                }
                let _ = resp.send(result);
            }
            IdaRequest::StackFrame { addr, resp } => {
                debug!(address = format!("{:#x}", addr), "Getting stack frame");
                let result = types::handle_stack_frame(&idb, addr);
                match &result {
                    Ok(r) => debug!(members = r.members.len(), "Got stack frame"),
                    Err(e) => warn!(error = %e, "Failed to get stack frame"),
                }
                let _ = resp.send(result);
            }
            IdaRequest::Structs {
                offset,
                limit,
                filter,
                resp,
            } => {
                debug!(offset, limit, filter = ?filter, "Listing structs");
                let result = structs::handle_structs(&idb, offset, limit, filter.as_deref());
                match &result {
                    Ok(r) => debug!(count = r.structs.len(), total = r.total, "Listed structs"),
                    Err(e) => warn!(error = %e, "Failed to list structs"),
                }
                let _ = resp.send(result);
            }
            IdaRequest::StructInfo {
                ordinal,
                name,
                resp,
            } => {
                debug!(ordinal = ?ordinal, name = ?name, "Getting struct info");
                let result = structs::handle_struct_info(&idb, ordinal, name.as_deref());
                match &result {
                    Ok(info) => {
                        debug!(name = %info.name, ordinal = info.ordinal, "Got struct info")
                    }
                    Err(e) => warn!(error = %e, "Failed to get struct info"),
                }
                let _ = resp.send(result);
            }
            IdaRequest::ReadStruct {
                addr,
                ordinal,
                name,
                resp,
            } => {
                debug!(address = format!("{:#x}", addr), ordinal = ?ordinal, name = ?name, "Reading struct");
                let result = structs::handle_read_struct(&idb, addr, ordinal, name.as_deref());
                match &result {
                    Ok(info) => debug!(name = %info.name, ordinal = info.ordinal, "Read struct"),
                    Err(e) => warn!(error = %e, "Failed to read struct"),
                }
                let _ = resp.send(result);
            }
            IdaRequest::XRefsTo { addr, resp } => {
                debug!(address = format!("{:#x}", addr), "Getting xrefs to");
                let result = xrefs::handle_xrefs_to(&idb, addr);
                match &result {
                    Ok(refs) => debug!(count = refs.len(), "Got xrefs to"),
                    Err(e) => warn!(error = %e, "Failed to get xrefs"),
                }
                let _ = resp.send(result);
            }
            IdaRequest::XRefsFrom { addr, resp } => {
                debug!(address = format!("{:#x}", addr), "Getting xrefs from");
                let result = xrefs::handle_xrefs_from(&idb, addr);
                match &result {
                    Ok(refs) => debug!(count = refs.len(), "Got xrefs from"),
                    Err(e) => warn!(error = %e, "Failed to get xrefs"),
                }
                let _ = resp.send(result);
            }
            IdaRequest::XRefsToField {
                ordinal,
                name,
                member_index,
                member_name,
                limit,
                resp,
            } => {
                debug!(
                    ordinal = ?ordinal,
                    name = ?name,
                    member_index = ?member_index,
                    member_name = ?member_name,
                    limit,
                    "Getting xrefs to struct field"
                );
                let result = structs::handle_xrefs_to_field(
                    &idb,
                    ordinal,
                    name.as_deref(),
                    member_index,
                    member_name.as_deref(),
                    limit,
                );
                match &result {
                    Ok(refs) => debug!(count = refs.xrefs.len(), "Got xrefs to struct field"),
                    Err(e) => warn!(error = %e, "Failed to get xrefs to struct field"),
                }
                let _ = resp.send(result);
            }
            IdaRequest::Imports {
                offset,
                limit,
                resp,
            } => {
                debug!(offset, limit, "Listing imports");
                let result = imports::handle_imports(&idb, offset, limit);
                match &result {
                    Ok(imps) => debug!(count = imps.len(), "Listed imports"),
                    Err(e) => warn!(error = %e, "Failed to list imports"),
                }
                let _ = resp.send(result);
            }
            IdaRequest::Exports {
                offset,
                limit,
                resp,
            } => {
                debug!(offset, limit, "Listing exports");
                let result = imports::handle_exports(&idb, offset, limit);
                match &result {
                    Ok(exps) => debug!(count = exps.len(), "Listed exports"),
                    Err(e) => warn!(error = %e, "Failed to list exports"),
                }
                let _ = resp.send(result);
            }
            IdaRequest::Entrypoints { resp } => {
                debug!("Listing entrypoints");
                let result = imports::handle_entrypoints(&idb);
                match &result {
                    Ok(eps) => debug!(count = eps.len(), "Listed entrypoints"),
                    Err(e) => warn!(error = %e, "Failed to list entrypoints"),
                }
                let _ = resp.send(result);
            }
            IdaRequest::GetBytes {
                addr,
                name,
                offset,
                size,
                resp,
            } => {
                let addr_log = addr
                    .map(|a| format!("{a:#x}"))
                    .unwrap_or_else(|| "none".to_string());
                debug!(
                    address = addr_log,
                    name = ?name,
                    offset,
                    size,
                    "Getting bytes"
                );
                let result = memory::handle_get_bytes(&idb, addr, name.as_deref(), offset, size);
                match &result {
                    Ok(b) => debug!(length = b.length, "Got bytes"),
                    Err(e) => warn!(error = %e, "Failed to get bytes"),
                }
                let _ = resp.send(result);
            }
            IdaRequest::SetComments {
                addr,
                name,
                offset,
                comment,
                repeatable,
                resp,
            } => {
                let addr_log = addr
                    .map(|a| format!("{a:#x}"))
                    .unwrap_or_else(|| "none".to_string());
                debug!(
                    address = addr_log,
                    name = ?name,
                    offset,
                    repeatable,
                    "Setting comment"
                );
                let result = annotations::handle_set_comments(
                    &idb,
                    addr,
                    name.as_deref(),
                    offset,
                    &comment,
                    repeatable,
                );
                if let Err(e) = &result {
                    warn!(error = %e, "Failed to set comment");
                }
                let _ = resp.send(result);
            }
            IdaRequest::Rename {
                addr,
                current_name,
                new_name,
                flags,
                resp,
            } => {
                let addr_log = addr
                    .map(|a| format!("{a:#x}"))
                    .unwrap_or_else(|| "none".to_string());
                debug!(
                    address = addr_log,
                    current_name = ?current_name,
                    flags,
                    "Renaming symbol"
                );
                let result = annotations::handle_rename(
                    &idb,
                    addr,
                    current_name.as_deref(),
                    &new_name,
                    flags,
                );
                if let Err(e) = &result {
                    warn!(error = %e, "Failed to rename");
                }
                let _ = resp.send(result);
            }
            IdaRequest::PatchBytes {
                addr,
                name,
                offset,
                bytes,
                resp,
            } => {
                let addr_log = addr
                    .map(|a| format!("{a:#x}"))
                    .unwrap_or_else(|| "none".to_string());
                debug!(
                    address = addr_log,
                    name = ?name,
                    offset,
                    length = bytes.len(),
                    "Patching bytes"
                );
                let result =
                    memory::handle_patch_bytes(&idb, addr, name.as_deref(), offset, &bytes);
                if let Err(e) = &result {
                    warn!(error = %e, "Failed to patch bytes");
                }
                let _ = resp.send(result);
            }
            IdaRequest::PatchAsm {
                addr,
                name,
                offset,
                line,
                resp,
            } => {
                let addr_log = addr
                    .map(|a| format!("{a:#x}"))
                    .unwrap_or_else(|| "none".to_string());
                debug!(
                    address = addr_log,
                    name = ?name,
                    offset,
                    line = %line,
                    "Patching asm"
                );
                let result = memory::handle_patch_asm(&idb, addr, name.as_deref(), offset, &line);
                if let Err(e) = &result {
                    warn!(error = %e, "Failed to patch asm");
                }
                let _ = resp.send(result);
            }
            IdaRequest::BasicBlocks { addr, resp } => {
                debug!(address = format!("{:#x}", addr), "Getting basic blocks");
                let result = controlflow::handle_basic_blocks(&idb, addr);
                match &result {
                    Ok(bbs) => debug!(count = bbs.len(), "Got basic blocks"),
                    Err(e) => warn!(error = %e, "Failed to get basic blocks"),
                }
                let _ = resp.send(result);
            }
            IdaRequest::Callees { addr, resp } => {
                debug!(address = format!("{:#x}", addr), "Getting callees");
                let result = controlflow::handle_callees(&idb, addr);
                match &result {
                    Ok(funcs) => debug!(count = funcs.len(), "Got callees"),
                    Err(e) => warn!(error = %e, "Failed to get callees"),
                }
                let _ = resp.send(result);
            }
            IdaRequest::Callers { addr, resp } => {
                debug!(address = format!("{:#x}", addr), "Getting callers");
                let result = controlflow::handle_callers(&idb, addr);
                match &result {
                    Ok(funcs) => debug!(count = funcs.len(), "Got callers"),
                    Err(e) => warn!(error = %e, "Failed to get callers"),
                }
                let _ = resp.send(result);
            }
            IdaRequest::IdbMeta { resp } => {
                debug!("Getting IDB metadata");
                let result = globals::handle_idb_meta(&idb);
                let _ = resp.send(result);
            }
            IdaRequest::LookupFunctions { queries, resp } => {
                debug!(count = queries.len(), "Looking up functions");
                let result = functions::handle_lookup_funcs(&idb, &queries);
                let _ = resp.send(result);
            }
            IdaRequest::ListGlobals {
                query,
                offset,
                limit,
                resp,
            } => {
                debug!(offset, limit, query = ?query, "Listing globals");
                let result = globals::handle_list_globals(&idb, query.as_deref(), offset, limit);
                let _ = resp.send(result);
            }
            IdaRequest::AnalyzeStrings {
                query,
                offset,
                limit,
                resp,
            } => {
                debug!(offset, limit, query = ?query, "Analyzing strings");
                let result = strings::handle_analyze_strings(&idb, query.as_deref(), offset, limit);
                let _ = resp.send(result);
            }
            IdaRequest::FindString {
                query,
                exact,
                case_insensitive,
                offset,
                limit,
                resp,
            } => {
                debug!(
                    query = %query,
                    exact,
                    case_insensitive,
                    offset,
                    limit,
                    "Finding strings"
                );
                let result = strings::handle_find_string(
                    &idb,
                    &query,
                    exact,
                    case_insensitive,
                    offset,
                    limit,
                );
                let _ = resp.send(result);
            }
            IdaRequest::XrefsToString {
                query,
                exact,
                case_insensitive,
                offset,
                limit,
                max_xrefs,
                resp,
            } => {
                debug!(
                    query = %query,
                    exact,
                    case_insensitive,
                    offset,
                    limit,
                    max_xrefs,
                    "Getting xrefs to strings"
                );
                let result = strings::handle_xrefs_to_string(
                    &idb,
                    &query,
                    exact,
                    case_insensitive,
                    offset,
                    limit,
                    max_xrefs,
                );
                let _ = resp.send(result);
            }
            IdaRequest::AnalyzeFuncs { resp } => {
                debug!("Running auto-analysis");
                let result = functions::handle_analyze_funcs(&mut idb);
                let _ = resp.send(result);
            }
            IdaRequest::FindBytes {
                pattern,
                max_results,
                resp,
            } => {
                debug!(pattern = %pattern, max_results, "Finding bytes");
                let result = search::handle_find_bytes(&idb, &pattern, max_results);
                let _ = resp.send(result);
            }
            IdaRequest::SearchText {
                text,
                max_results,
                resp,
            } => {
                debug!(text = %text, max_results, "Searching text");
                let result = search::handle_search_text(&idb, &text, max_results);
                let _ = resp.send(result);
            }
            IdaRequest::SearchImm {
                imm,
                max_results,
                resp,
            } => {
                debug!(imm, max_results, "Searching immediate");
                let result = search::handle_search_imm(&idb, imm, max_results);
                let _ = resp.send(result);
            }
            IdaRequest::FindInsns {
                patterns,
                max_results,
                case_insensitive,
                resp,
            } => {
                debug!(
                    patterns = ?patterns,
                    max_results,
                    case_insensitive,
                    "Finding instruction sequences"
                );
                let result =
                    search::handle_find_insns(&idb, &patterns, max_results, case_insensitive);
                let _ = resp.send(result);
            }
            IdaRequest::FindInsnOperands {
                patterns,
                max_results,
                case_insensitive,
                resp,
            } => {
                debug!(
                    patterns = ?patterns,
                    max_results,
                    case_insensitive,
                    "Finding instruction operands"
                );
                let result = search::handle_find_insn_operands(
                    &idb,
                    &patterns,
                    max_results,
                    case_insensitive,
                );
                let _ = resp.send(result);
            }
            IdaRequest::ReadInt { addr, size, resp } => {
                debug!(address = format!("{:#x}", addr), size, "Reading int");
                let result = memory::handle_read_int(&idb, addr, size);
                let _ = resp.send(result);
            }
            IdaRequest::GetString {
                addr,
                max_len,
                resp,
            } => {
                debug!(address = format!("{:#x}", addr), max_len, "Reading string");
                let result = strings::handle_get_string(&idb, addr, max_len);
                let _ = resp.send(result);
            }
            IdaRequest::GetGlobalValue { query, resp } => {
                debug!(query = %query, "Getting global value");
                let result = globals::handle_get_global_value(&idb, &query);
                let _ = resp.send(result);
            }
            IdaRequest::FindPaths {
                start,
                end,
                max_paths,
                max_depth,
                resp,
            } => {
                debug!(
                    start = format!("{:#x}", start),
                    end = format!("{:#x}", end),
                    max_paths,
                    max_depth,
                    "Finding paths"
                );
                let result = controlflow::handle_find_paths(&idb, start, end, max_paths, max_depth);
                let _ = resp.send(result);
            }
            IdaRequest::CallGraph {
                addr,
                max_depth,
                max_nodes,
                resp,
            } => {
                debug!(
                    address = format!("{:#x}", addr),
                    max_depth, max_nodes, "Building call graph"
                );
                let result = controlflow::handle_callgraph(&idb, addr, max_depth, max_nodes);
                let _ = resp.send(result);
            }
            IdaRequest::XrefMatrix { addrs, resp } => {
                debug!(count = addrs.len(), "Building xref matrix");
                let result = xrefs::handle_xref_matrix(&idb, &addrs);
                let _ = resp.send(result);
            }
            IdaRequest::ExportFuncs {
                offset,
                limit,
                resp,
            } => {
                debug!(offset, limit, "Exporting functions");
                let result = functions::handle_list_functions(&idb, offset, limit, None);
                let _ = resp.send(result);
            }
            IdaRequest::PseudocodeAt {
                addr,
                end_addr,
                resp,
            } => {
                debug!(
                    address = format!("{:#x}", addr),
                    end_addr = end_addr.map(|a| format!("{:#x}", a)),
                    "Getting pseudocode at address"
                );
                let result = disasm::handle_pseudocode_at(&idb, addr, end_addr);
                match &result {
                    Ok(v) => debug!(
                        count = v
                            .get("statements")
                            .and_then(|s| s.as_array())
                            .map(|a| a.len())
                            .unwrap_or(0),
                        "Got pseudocode at address"
                    ),
                    Err(e) => {
                        warn!(address = format!("{:#x}", addr), error = %e, "Failed to get pseudocode")
                    }
                }
                let _ = resp.send(result);
            }
            IdaRequest::RunScript { code, resp } => {
                debug!(code_len = code.len(), "Running script");
                let started = std::time::Instant::now();
                let result = script::handle_run_script(&idb, &code);
                let elapsed_ms = started.elapsed().as_millis();
                match &result {
                    Ok(value) => {
                        let success = value.get("success").and_then(|v| v.as_bool()) == Some(true);
                        let stdout_len = value
                            .get("stdout")
                            .and_then(|v| v.as_str())
                            .map(|s| s.len())
                            .unwrap_or(0);
                        let stderr_len = value
                            .get("stderr")
                            .and_then(|v| v.as_str())
                            .map(|s| s.len())
                            .unwrap_or(0);
                        if success {
                            debug!(elapsed_ms, stdout_len, stderr_len, "Script executed");
                        } else {
                            let error = value.get("error").and_then(|v| v.as_str()).unwrap_or("");
                            warn!(
                                elapsed_ms,
                                stdout_len, stderr_len, error, "Script execution reported failure"
                            );
                        }
                    }
                    Err(e) => {
                        warn!(elapsed_ms, error = %e, "Failed to execute script");
                    }
                }
                let _ = resp.send(result);
            }
            IdaRequest::Shutdown => {
                info!("Worker shutting down");
                shutdown_cleanup(&mut idb, &mut lock_file, &mut lock_path);
                break;
            }
        }
    }
}

fn shutdown_cleanup(
    idb: &mut Option<IDB>,
    lock_file: &mut Option<File>,
    lock_path: &mut Option<PathBuf>,
) {
    // Explicitly close database to ensure IDA packs it before exit.
    if idb.take().is_some() {
        info!("Closing database before shutdown");
    }
    release_mcp_lock(lock_file, lock_path);
}

/// Send a version-mismatch error for every request variant so the
/// agent gets a clear message instead of a segfault.
fn reject_with_version_error(req: IdaRequest, msg: &str) {
    let err = ToolError::SdkVersionMismatch(msg.to_owned());

    /// Helper: send `Err(err)` on a `oneshot::Sender<Result<T, ToolError>>`.
    macro_rules! reject {
        ($resp:expr, $err:expr) => {{
            let _ = $resp.send(Err($err));
        }};
    }

    match req {
        IdaRequest::Shutdown => {} // always honour shutdown
        IdaRequest::Close { resp } => {
            let _ = resp.send(());
        }
        IdaRequest::Open { resp, .. } => reject!(resp, err),
        IdaRequest::LoadDebugInfo { resp, .. } => reject!(resp, err),
        IdaRequest::AnalysisStatus { resp, .. } => reject!(resp, err),
        IdaRequest::ListFunctions { resp, .. } => reject!(resp, err),
        IdaRequest::ResolveFunction { resp, .. } => reject!(resp, err),
        IdaRequest::DisasmByName { resp, .. } => reject!(resp, err),
        IdaRequest::Disasm { resp, .. } => reject!(resp, err),
        IdaRequest::Decompile { resp, .. } => reject!(resp, err),
        IdaRequest::Segments { resp, .. } => reject!(resp, err),
        IdaRequest::Strings { resp, .. } => reject!(resp, err),
        IdaRequest::LocalTypes { resp, .. } => reject!(resp, err),
        IdaRequest::DeclareType { resp, .. } => reject!(resp, err),
        IdaRequest::ApplyTypes { resp, .. } => reject!(resp, err),
        IdaRequest::InferTypes { resp, .. } => reject!(resp, err),
        IdaRequest::AddrInfo { resp, .. } => reject!(resp, err),
        IdaRequest::FunctionAt { resp, .. } => reject!(resp, err),
        IdaRequest::DisasmFunctionAt { resp, .. } => reject!(resp, err),
        IdaRequest::DeclareStack { resp, .. } => reject!(resp, err),
        IdaRequest::DeleteStack { resp, .. } => reject!(resp, err),
        IdaRequest::StackFrame { resp, .. } => reject!(resp, err),
        IdaRequest::Structs { resp, .. } => reject!(resp, err),
        IdaRequest::StructInfo { resp, .. } => reject!(resp, err),
        IdaRequest::ReadStruct { resp, .. } => reject!(resp, err),
        IdaRequest::XRefsTo { resp, .. } => reject!(resp, err),
        IdaRequest::XRefsFrom { resp, .. } => reject!(resp, err),
        IdaRequest::XRefsToField { resp, .. } => reject!(resp, err),
        IdaRequest::Imports { resp, .. } => reject!(resp, err),
        IdaRequest::Exports { resp, .. } => reject!(resp, err),
        IdaRequest::Entrypoints { resp, .. } => reject!(resp, err),
        IdaRequest::GetBytes { resp, .. } => reject!(resp, err),
        IdaRequest::SetComments { resp, .. } => reject!(resp, err),
        IdaRequest::Rename { resp, .. } => reject!(resp, err),
        IdaRequest::PatchBytes { resp, .. } => reject!(resp, err),
        IdaRequest::PatchAsm { resp, .. } => reject!(resp, err),
        IdaRequest::BasicBlocks { resp, .. } => reject!(resp, err),
        IdaRequest::Callees { resp, .. } => reject!(resp, err),
        IdaRequest::Callers { resp, .. } => reject!(resp, err),
        IdaRequest::IdbMeta { resp, .. } => reject!(resp, err),
        IdaRequest::LookupFunctions { resp, .. } => reject!(resp, err),
        IdaRequest::ListGlobals { resp, .. } => reject!(resp, err),
        IdaRequest::AnalyzeStrings { resp, .. } => reject!(resp, err),
        IdaRequest::FindString { resp, .. } => reject!(resp, err),
        IdaRequest::XrefsToString { resp, .. } => reject!(resp, err),
        IdaRequest::AnalyzeFuncs { resp, .. } => reject!(resp, err),
        IdaRequest::FindBytes { resp, .. } => reject!(resp, err),
        IdaRequest::SearchText { resp, .. } => reject!(resp, err),
        IdaRequest::SearchImm { resp, .. } => reject!(resp, err),
        IdaRequest::FindInsns { resp, .. } => reject!(resp, err),
        IdaRequest::FindInsnOperands { resp, .. } => reject!(resp, err),
        IdaRequest::ReadInt { resp, .. } => reject!(resp, err),
        IdaRequest::GetString { resp, .. } => reject!(resp, err),
        IdaRequest::GetGlobalValue { resp, .. } => reject!(resp, err),
        IdaRequest::FindPaths { resp, .. } => reject!(resp, err),
        IdaRequest::CallGraph { resp, .. } => reject!(resp, err),
        IdaRequest::XrefMatrix { resp, .. } => reject!(resp, err),
        IdaRequest::ExportFuncs { resp, .. } => reject!(resp, err),
        IdaRequest::PseudocodeAt { resp, .. } => reject!(resp, err),
        IdaRequest::RunScript { resp, .. } => reject!(resp, err),
    }
}
