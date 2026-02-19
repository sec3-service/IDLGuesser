mod client;
mod dynamic_analysis;
mod idl;
mod static_analysis;

use anchor_lang::prelude::Pubkey as Pk;
use anyhow::{anyhow, Result};
use clap::Parser;
use dynamic_analysis::extract_args;
use dynamic_analysis::extract_types;
use idl::{Idl, InstructionInfo, Metadata};
use log::debug;
use solana_pubkey::Pubkey;
use solana_sbpf::{ebpf, static_analysis::Analysis};
use solana_sdk::hash::hash;
use static_analysis::{
    extract_accounts, extract_ix_accounts, find_account_deserializer, find_instruction_handlers,
    generate_call_graph, is_anchor_program, load_executable,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Write};
use std::str::FromStr;

use crate::idl::output_file_path;

#[derive(Parser, Debug)]
struct Opts {
    #[arg(help = "The program ID to analyze")]
    program_id: String,
    #[arg(short, long, default_value_t = String::from("https://api.mainnet-beta.solana.com"), help = "Solana JSON RPC endpoint")]
    url: String,
    #[arg(short, long, help = "Verbose logging")]
    verbose: bool,
    #[arg(short, long, help = "Force guess the IDL even if a public IDL exists")]
    force_guess: bool,
    #[arg(long, help = "Export the disassembled assembly code to asm.txt")]
    export_asm: bool,
    #[arg(short, long, help = "Input file for the program executable data")]
    input: Option<String>,
    #[arg(short, long, help = "Output file for the IDL")]
    output: Option<String>,
}

fn main() -> Result<()> {
    let opts = Opts::parse();
    let client = client::create_client(&opts.url);
    let program_anchor_pk = Pk::from_str(&opts.program_id)?;
    let program_id = Pubkey::new_from_array(program_anchor_pk.to_bytes());

    if opts.verbose {
        std::env::set_var("RUST_LOG", "debug");
    }
    env_logger::init();

    if !opts.force_guess {
        if let Ok(account) = client::get_idl_account(&client, &program_anchor_pk) {
            let idl_path = output_file_path(program_id, opts.output);
            let mut file = File::create(&idl_path)?;
            file.write_all(serde_json::to_string_pretty(&account)?.as_bytes())?;
            println!("Public IDL found for {}, saved to {}", program_id, idl_path);
            return Ok(());
        }
    }

    let executable_data = if opts.input.is_some() {
        let mut file = File::open(opts.input.unwrap())?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        data
    } else {
        client::get_executable(&client, &program_id)?
    };

    if !is_anchor_program(&executable_data) {
        return Err(anyhow!("Program is not an anchor program"));
    }

    let executable = load_executable(&executable_data, &program_id)?;

    let sbpf_version = executable.get_sbpf_version();
    debug_assert!(!sbpf_version.static_syscalls());
    let function_registry = executable.get_function_registry();

    // Run sbpf built-in analysis
    let analysis = Analysis::from_executable(&executable).expect("Failed to analyze program");

    if opts.export_asm {
        let mut output = File::create("asm.txt")?;
        analysis.disassemble(&mut output)?;
    }

    // Get ptr to instruction mapping
    let (_program_vm_addr, program) = executable.get_text_bytes();
    let mut instructions: BTreeMap<usize, ebpf::Insn> = BTreeMap::new();
    let mut insn_ptr: usize = 0;
    while insn_ptr * ebpf::INSN_SIZE < program.len() {
        let mut insn = ebpf::get_insn_unchecked(program, insn_ptr);
        if insn.opc == ebpf::LD_DW_IMM {
            insn_ptr += 1;
            if insn_ptr * ebpf::INSN_SIZE >= program.len() {
                break;
            }
            ebpf::augment_lddw_unchecked(program, &mut insn);
        }
        instructions.insert(insn.ptr, insn);
        insn_ptr += 1;
    }

    // Use the start of the next function as the end of the current function
    let function_ranges: BTreeMap<_, _> = analysis
        .functions
        .keys()
        .zip(
            analysis
                .functions
                .keys()
                .skip(1)
                .chain(std::iter::once(&insn_ptr)),
        )
        .map(|(start, end)| (*start, (*start, *end)))
        .collect();

    let (call_graph, reference_graph) =
        generate_call_graph(&executable, &function_ranges, &instructions)?;

    let (instruction_handlers, possible_signer_error) = find_instruction_handlers(
        &executable,
        &function_ranges,
        &instructions,
        &executable_data,
    )?;

    let deserializers = find_account_deserializer(
        &function_ranges,
        &instructions,
        &reference_graph,
        &executable_data,
    );

    debug!("possible_signer_error: {:?}", possible_signer_error);

    let signer_try_from_pc = match possible_signer_error {
        Some(pc) => reference_graph.get(&pc).and_then(|x| x.first().cloned()),
        None => None,
    };
    debug!("signer_try_from_pc: {:?}", signer_try_from_pc);

    let mut instruction_infos = Vec::new();
    for (instruction, function_start) in instruction_handlers {
        debug!("");
        debug!(
            "Instruction {} {}",
            instruction,
            instructions.get(&function_start).unwrap().ptr
        );
        let mut discriminator = [0u8; 8];
        discriminator
            .copy_from_slice(&hash(format!("global:{instruction}").as_bytes()).to_bytes()[..8]);

        let (&_try_accounts_func, accounts) = call_graph
            .get(&function_start)
            .unwrap_or(&BTreeSet::new())
            .iter()
            .map(|callee| {
                let (start, end) = function_ranges.get(callee).unwrap();
                let result = extract_ix_accounts(
                    &analysis,
                    &instructions
                        .range(start..end)
                        .map(|(_, insn)| insn)
                        .collect::<Vec<&ebpf::Insn>>(),
                    function_registry,
                    &sbpf_version,
                    &executable_data,
                    signer_try_from_pc,
                )
                .unwrap_or_default();
                (callee, result)
            })
            .max_by_key(|(_, result)| result.len())
            .unwrap();

        instruction_infos.push(InstructionInfo {
            name: instruction,
            discriminator,
            accounts,
            args: extract_args(&executable_data, function_start),
        });
    }

    let idl = Idl {
        address: program_id.to_string(),
        metadata: Metadata {
            name: "IDL".to_string(),
            version: "1.0.0".to_string(),
            spec: "0.1.0".to_string(),
            description: "Generated by IDL Guesser".to_string(),
        },
        instructions: instruction_infos,
        accounts: extract_accounts(&function_ranges, &instructions, &executable_data),
        errors: vec![],
        types: extract_types(&executable_data, &deserializers),
    };

    println!("Generated IDL for {}", program_id);
    let idl_path = output_file_path(program_id, opts.output);
    let mut file = File::create(&idl_path)?;
    file.write_all(serde_json::to_string_pretty(&idl)?.as_bytes())?;
    println!("Saved IDL to {}", idl_path);

    Ok(())
}