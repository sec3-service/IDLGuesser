use crate::idl::{AccountMeta, IDLAccount};
use anyhow::{anyhow, Result};
use heck::ToSnakeCase;
use log::debug;
use solana_bpf_loader_program::{
    load_program_from_bytes, syscalls::create_program_runtime_environment_v1,
};
use solana_program_runtime::{
    invoke_context::InvokeContext,
    loaded_programs::{LoadProgramMetrics, ProgramCacheEntryType},
    with_mock_invoke_context,
};
use solana_sbpf::{
    ebpf,
    elf::Executable,
    program::{FunctionRegistry, SBPFVersion},
    static_analysis::Analysis,
};
use solana_sdk::{bpf_loader_upgradeable, hash::hash, pubkey::Pubkey, slot_history::Slot};
use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};

const CONSTRAINT_MUT: i64 = 2000;
const CONSTRAINT_SIGNER: i64 = 2002;
const CONSTRAINT_RENT_EXEMPT: i64 = 2005;
const CONSTRAINT_SEEDS: i64 = 2006;
const ACCOUNT_DISCRIMINATOR_NOT_FOUND: i64 = 3001;
const ACCOUNT_NOT_ENOUGH_KEYS: i64 = 3005;
const ACCOUNT_NOT_SIGNER: i64 = 3010;

const BUILTIN_IXS: [&str; 7] = [
    "IdlCreateAccount",
    "IdlResizeAccount",
    "IdlCloseAccount",
    "IdlCreateBuffer",
    "IdlWrite",
    "IdlSetAuthority",
    "IdlSetBuffer",
];

type FunctionGraph = BTreeMap<usize, BTreeSet<usize>>;

pub fn extract_ix_accounts(
    analysis: &Analysis,
    instructions: &[&ebpf::Insn],
    function_registry: &FunctionRegistry<usize>,
    sbpf_version: &SBPFVersion,
    executable_data: &[u8],
    signer_try_from_pc: Option<usize>,
) -> Result<Vec<AccountMeta>, &'static str> {
    let mut accounts: HashSet<String> = HashSet::new();
    let mut accountmetas: Vec<AccountMeta> = Vec::new();
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    queue.push_back(
        analysis
            .cfg_nodes
            .get(&instructions[0].ptr)
            .ok_or("Failed to get CFG node")?,
    );

    debug!("{}", queue[0].label);

    while let Some(node) = queue.pop_front() {
        if !visited.insert(node.label.clone()) {
            continue;
        }

        // TODO: concat nodes connected with JA
        'child_loop: for &dest in &node.destinations {
            let mut child_node = analysis
                .cfg_nodes
                .get(&dest)
                .ok_or("Failed to get CFG node")?;
            while child_node.instructions.len() == 1 && child_node.destinations.len() == 1 {
                child_node = analysis.cfg_nodes.get(&child_node.destinations[0]).unwrap();
            }
            for pc in child_node.instructions.start + 2..child_node.instructions.end {
                let insn = analysis.instructions.get(pc).unwrap();
                if insn.opc != ebpf::CALL_IMM {
                    continue;
                }
                let lddw_inst = analysis.instructions.get(pc - 2).unwrap();
                let mov64_inst = analysis.instructions.get(pc - 1).unwrap();
                if !matches!(
                    (lddw_inst.opc, lddw_inst.dst, mov64_inst.opc, mov64_inst.dst),
                    (ebpf::LD_DW_IMM, 4, ebpf::MOV64_IMM, 5)
                ) {
                    // Handle init placeholder
                    if mov64_inst.dst == 2 && mov64_inst.imm == ACCOUNT_NOT_ENOUGH_KEYS {
                        // need to make sure this is not try_accounts for UncheckedAccount and Sysvar
                        // TODO: is this enough?
                        if child_node.destinations.len() == 1 {
                            let mut have_lddw = child_node.instructions.clone().any(|idx| {
                                analysis.instructions.get(idx).unwrap().opc == ebpf::LD_DW_IMM
                            });
                            let last_insn = analysis
                                .instructions
                                .get(child_node.instructions.end - 1)
                                .unwrap();
                            if last_insn.opc == ebpf::JA {
                                let next_node =
                                    analysis.cfg_nodes.get(&child_node.destinations[0]).unwrap();
                                have_lddw |= next_node.instructions.clone().any(|idx| {
                                    analysis.instructions.get(idx).unwrap().opc == ebpf::LD_DW_IMM
                                });
                            }
                            if !have_lddw {
                                debug!("    Add placeholder here: {}", child_node.label);
                                accountmetas.push(AccountMeta {
                                    name: "INIT_PLACEHOLDER".to_string(),
                                    signer: false,
                                    writable: false,
                                });
                            }
                        }
                    }
                    continue;
                }
                // Recover account name from error message
                let offset = lddw_inst.imm as usize & 0xffffffff;
                let length = mov64_inst.imm as usize;
                let account_name =
                    String::from_utf8_lossy(&executable_data[offset..offset + length]).to_string();

                if !accounts.contains(&account_name) {
                    debug!("    {} {}", child_node.label, account_name);
                    // Check if the account is a signer
                    let mut is_signer = false;
                    for call_site in node.instructions.start + 2..node.instructions.end {
                        let insn = analysis.instructions.get(call_site).unwrap();
                        if insn.opc != ebpf::CALL_IMM {
                            continue;
                        }
                        let key = sbpf_version.calculate_call_imm_target_pc(insn.ptr, insn.imm);
                        let (_, callee) = function_registry.lookup_by_key(key).unwrap();
                        if signer_try_from_pc == Some(callee) {
                            is_signer = true;
                            break;
                        }
                    }
                    accounts.insert(account_name.clone());
                    accountmetas.push(AccountMeta {
                        name: account_name,
                        signer: is_signer,
                        writable: false,
                    });
                } else {
                    debug!("    constraint {} {}", child_node.label, account_name);
                    for call_site in child_node.instructions.start + 2..child_node.instructions.end
                    {
                        let insn = analysis.instructions.get(call_site).unwrap();
                        let mov64_inst = analysis.instructions.get(call_site - 1).unwrap();
                        if !matches!(
                            (insn.opc, mov64_inst.opc, mov64_inst.dst),
                            (ebpf::CALL_IMM, ebpf::MOV64_IMM, 2)
                        ) {
                            continue;
                        }
                        match mov64_inst.imm {
                            CONSTRAINT_MUT => {
                                debug!("        mut");
                                for account in accountmetas.iter_mut() {
                                    if account.name == account_name {
                                        account.writable = true;
                                    }
                                }
                            }
                            CONSTRAINT_SIGNER => {
                                debug!("        signer");
                                for account in accountmetas.iter_mut() {
                                    if account.name == account_name {
                                        account.signer = true;
                                    }
                                }
                            }
                            CONSTRAINT_RENT_EXEMPT => {
                                debug!("        init");
                                // Replace the first placeholder with the account
                                let original_account = accountmetas
                                    .iter()
                                    .find(|account| account.name == account_name)
                                    .unwrap()
                                    .clone();
                                accountmetas.retain(|account| account.name != account_name);
                                for account in accountmetas.iter_mut() {
                                    if account.name == "INIT_PLACEHOLDER" {
                                        account.name = account_name.clone();
                                        account.signer = original_account.signer;
                                        account.writable = original_account.writable;
                                        break;
                                    }
                                }
                            }
                            CONSTRAINT_SEEDS => {
                                debug!("        PDA");
                            }
                            _ => {}
                        }
                    }
                }
                continue 'child_loop;
            }
            queue.push_back(child_node);
        }
    }

    // Remove additional placeholder, should not happen in normal cases
    accountmetas.retain(|account| account.name != "INIT_PLACEHOLDER");

    Ok(accountmetas)
}

pub fn is_anchor_program(executable_data: &[u8]) -> bool {
    let sig = b"AnchorError occurred. Error Code: ";
    executable_data
        .windows(sig.len())
        .any(|window| window == sig)
}

pub fn load_executable(
    executable_data: &[u8],
    program_id: &Pubkey,
) -> Result<Executable<InvokeContext<'static>>> {
    let transaction_accounts = Vec::new();
    with_mock_invoke_context!(invoke_context, transaction_context, transaction_accounts);

    // Prepare program runtime environment
    let program_runtime_environment = create_program_runtime_environment_v1(
        invoke_context.get_feature_set(),
        invoke_context.get_compute_budget(),
        false,
        true,
    )
    .map_err(|e| anyhow!("Failed to create program runtime environment: {}", e))?;

    let mut load_program_metrics = LoadProgramMetrics {
        program_id: program_id.to_string(),
        ..Default::default()
    };

    // Load program
    load_program_from_bytes(
        invoke_context.get_log_collector(),
        &mut load_program_metrics,
        executable_data,
        &bpf_loader_upgradeable::id(),
        executable_data.len(),
        Slot::default(),
        Arc::new(program_runtime_environment),
        false,
    )
    .map_err(|e| anyhow!("Failed to load program: {}", e))
    .map(|loaded_program| match loaded_program.program {
        ProgramCacheEntryType::Loaded(program) => program,
        _ => unreachable!(),
    })
}

pub fn generate_call_graph(
    executable: &Executable<InvokeContext<'static>>,
    function_ranges: &BTreeMap<usize, (usize, usize)>,
    instructions: &BTreeMap<usize, ebpf::Insn>,
) -> Result<(FunctionGraph, FunctionGraph)> {
    let mut call_graph = FunctionGraph::new();
    let mut reference_graph = FunctionGraph::new();

    // Analyze each function's instructions
    for &(function_start, function_end) in function_ranges.values() {
        let mut call_targets = BTreeSet::new();

        // Process each instruction in the function
        for pc in function_start..function_end {
            let insn = match instructions.get(&pc) {
                Some(insn) => insn,
                None => continue,
            };

            if insn.opc != ebpf::CALL_IMM {
                continue;
            }

            let key = executable
                .get_sbpf_version()
                .calculate_call_imm_target_pc(insn.ptr, insn.imm);
            if let Some((_function_name, target_pc)) =
                executable.get_function_registry().lookup_by_key(key)
            {
                call_targets.insert(target_pc);
                reference_graph
                    .entry(target_pc)
                    .or_default()
                    .insert(function_start);
            }
        }

        call_graph.insert(function_start, call_targets);
    }

    Ok((call_graph, reference_graph))
}

pub fn find_instruction_handlers(
    executable: &Executable<InvokeContext<'static>>,
    function_ranges: &BTreeMap<usize, (usize, usize)>,
    instructions: &BTreeMap<usize, ebpf::Insn>,
    executable_data: &[u8],
) -> Result<(BTreeMap<String, usize>, Option<usize>)> {
    let mut instruction_handlers = BTreeMap::<String, usize>::new();
    let mut possible_signer_error = None;

    for &(function_start, function_end) in function_ranges.values() {
        for pc in function_start..function_end {
            let insn = match instructions.get(&pc) {
                Some(insn) => insn,
                None => continue,
            };

            match insn.opc {
                ebpf::CALL_IMM => {
                    let key = executable
                        .get_sbpf_version()
                        .calculate_call_imm_target_pc(insn.ptr, insn.imm);
                    if executable
                        .get_function_registry()
                        .lookup_by_key(key)
                        .is_some()
                    {
                        continue;
                    }

                    let (syscall_name_bytes, _) = match executable
                        .get_loader()
                        .get_function_registry()
                        .lookup_by_key(insn.imm as u32)
                    {
                        Some(pair) => pair,
                        None => continue,
                    };

                    let syscall_name = String::from_utf8_lossy(syscall_name_bytes).to_string();
                    if syscall_name != "sol_log_" {
                        continue;
                    }

                    let lddw_inst = match instructions.get(&(pc - 3)) {
                        Some(inst) => inst,
                        None => continue,
                    };
                    let mov64_inst = match instructions.get(&(pc - 1)) {
                        Some(inst) => inst,
                        None => continue,
                    };

                    if !matches!(
                        (lddw_inst.opc, lddw_inst.dst, mov64_inst.opc, mov64_inst.dst),
                        (ebpf::LD_DW_IMM, 1, ebpf::MOV64_IMM, 2)
                    ) {
                        continue;
                    }

                    let offset = (lddw_inst.imm as usize) & 0xffffffff;
                    let length = mov64_inst.imm as usize;
                    let sollog_str =
                        String::from_utf8_lossy(&executable_data[offset..offset + length]);

                    let sig = "Instruction: ";

                    if !sollog_str.starts_with(sig) {
                        continue;
                    }
                    let handler_name = &sollog_str[sig.len()..];

                    if BUILTIN_IXS.contains(&handler_name) {
                        continue;
                    }

                    instruction_handlers
                        .insert(handler_name.to_string().to_snake_case(), function_start);
                }
                ebpf::MOV64_IMM if insn.dst == 2 && insn.imm == ACCOUNT_NOT_SIGNER => {
                    possible_signer_error = Some(function_start);
                }
                _ => {}
            }
        }
    }

    Ok((instruction_handlers, possible_signer_error))
}

pub fn extract_accounts(
    function_ranges: &BTreeMap<usize, (usize, usize)>,
    instructions: &BTreeMap<usize, ebpf::Insn>,
    executable_data: &[u8],
) -> Vec<IDLAccount> {
    let mut accounts = Vec::new();

    for &(function_start, function_end) in function_ranges.values() {
        let mut flag = false;
        let mut account_name_offset = None;
        let mut account_name_length = None;
        for pc in function_start + 3..function_end {
            let insn = match instructions.get(&pc) {
                Some(insn) => insn,
                None => continue,
            };

            match insn.opc {
                ebpf::CALL_IMM => {
                    let lddw_inst = match instructions.get(&(pc - 3)) {
                        Some(inst) => inst,
                        None => continue,
                    };
                    let mov64_inst = match instructions.get(&(pc - 1)) {
                        Some(inst) => inst,
                        None => continue,
                    };

                    if !matches!(
                        (lddw_inst.opc, lddw_inst.dst, mov64_inst.opc, mov64_inst.dst),
                        (ebpf::LD_DW_IMM, 4, ebpf::MOV64_IMM, 5)
                    ) {
                        continue;
                    }

                    let offset = (lddw_inst.imm as usize) & 0xffffffff;
                    let length = mov64_inst.imm as usize;
                    account_name_offset = Some(offset);
                    account_name_length = Some(length);
                }
                ebpf::MOV64_IMM if insn.dst == 2 && insn.imm == ACCOUNT_DISCRIMINATOR_NOT_FOUND => {
                    flag = true;
                }
                _ => {}
            }
        }
        if flag && account_name_offset.is_some() && account_name_length.is_some() {
            let account_name = String::from_utf8_lossy(
                &executable_data[account_name_offset.unwrap()
                    ..account_name_offset.unwrap() + account_name_length.unwrap()],
            );
            if account_name == "IdlAccount" {
                continue;
            }
            let mut discriminator = [0u8; 8];
            discriminator.copy_from_slice(
                &hash(format!("account:{account_name}").as_bytes()).to_bytes()[..8],
            );
            accounts.push(IDLAccount {
                name: account_name.to_string(),
                discriminator,
            });
            debug!("{} {:?}", account_name, discriminator);
        }
    }

    accounts
}

pub fn find_account_deserializer(
    function_ranges: &BTreeMap<usize, (usize, usize)>,
    instructions: &BTreeMap<usize, ebpf::Insn>,
    reference_graph: &FunctionGraph,
    executable_data: &[u8],
) -> BTreeMap<String, usize> {
    let mut deserializers = BTreeMap::<String, usize>::new();

    for &(function_start, function_end) in function_ranges.values() {
        for pc in function_start..function_end {
            let insn = match instructions.get(&pc) {
                Some(insn) => insn,
                None => continue,
            };

            if insn.opc != ebpf::CALL_IMM {
                continue;
            }

            let prev_insn = match instructions.get(&(pc - 1)) {
                Some(insn) => insn,
                None => continue,
            };

            // Find mov64 r2, 3003 AccountDidNotDeserialize
            if prev_insn.opc == ebpf::MOV64_IMM && prev_insn.dst == 2 && prev_insn.imm == 3003 {
                for caller in reference_graph
                    .get(&function_start)
                    .unwrap_or(&BTreeSet::new())
                {
                    let caller_range = function_ranges.get(caller).unwrap();
                    for caller_pc in caller_range.0 + 2..caller_range.1 {
                        let call_insn = match instructions.get(&caller_pc) {
                            Some(insn) => insn,
                            None => continue,
                        };
                        if call_insn.opc != ebpf::CALL_IMM {
                            continue;
                        }
                        let lddw_inst = match instructions.get(&(caller_pc - 3)) {
                            Some(inst) => inst,
                            None => continue,
                        };
                        let mov64_inst = match instructions.get(&(caller_pc - 1)) {
                            Some(inst) => inst,
                            None => continue,
                        };

                        if !matches!(
                            (lddw_inst.opc, lddw_inst.dst, mov64_inst.opc, mov64_inst.dst),
                            (ebpf::LD_DW_IMM, 4, ebpf::MOV64_IMM, 5)
                        ) {
                            continue;
                        }

                        let offset = (lddw_inst.imm as usize) & 0xffffffff;
                        let length = mov64_inst.imm as usize;
                        let account_name =
                            String::from_utf8_lossy(&executable_data[offset..offset + length]);
                        if account_name == "IdlAccount" || !account_name.chars().next().unwrap().is_uppercase() {
                            continue;
                        }
                        deserializers.insert(account_name.to_string(), function_start);
                        debug!(
                            "Find deserializer for {} at {}",
                            account_name, function_start
                        );
                    }
                }
            }
        }
    }

    deserializers
}
