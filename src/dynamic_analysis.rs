use crate::idl::{ArgMeta, IDLType, InnerType};

use solana_sbpf::{
    aligned_memory::AlignedMemory,
    ebpf::{self, HOST_ALIGN},
    elf::Executable,
    interpreter::Interpreter,
    memory_region::{MemoryMapping, MemoryRegion},
    program::{BuiltinProgram, SBPFVersion},
    static_analysis::TraceLogEntry,
    vm::EbpfVm,
    vm::{Config, ContextObject},
};
use solana_type_overrides::sync::Arc;
use std::collections::BTreeMap;
use std::hash::{DefaultHasher, Hasher};

#[derive(Debug, Clone, Default)]
pub struct TestContextObject {
    /// Contains the register state at every instruction in order of execution
    pub trace_log: Vec<TraceLogEntry>,
    /// Maximal amount of instructions which still can be executed
    pub remaining: u64,
}

impl ContextObject for TestContextObject {
    fn trace(&mut self, state: [u64; 12]) {
        self.trace_log.push(state);
    }

    fn consume(&mut self, amount: u64) {
        self.remaining = self.remaining.saturating_sub(amount);
    }

    fn get_remaining(&self) -> u64 {
        self.remaining
    }
}

impl TestContextObject {
    /// Initialize with instruction meter
    pub fn new(remaining: u64) -> Self {
        Self {
            trace_log: Vec::new(),
            remaining,
        }
    }

    /// hash pc in trace log
    pub fn hash_trace_log(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        for state in &self.trace_log {
            hasher.write(&state[11].to_le_bytes());
        }
        hasher.finish()
    }
}

pub fn extract_args(executable_data: &[u8], entrypoint: usize) -> Vec<ArgMeta> {
    let config = Config {
        enabled_sbpf_versions: SBPFVersion::V0..=SBPFVersion::V3,
        enable_instruction_tracing: true,
        ..Config::default()
    };
    let loader = BuiltinProgram::new_loader(config.clone());
    let executable =
        Executable::<TestContextObject>::from_elf(executable_data, Arc::new(loader)).unwrap();
    let sbpf_version = executable.get_sbpf_version();
    let program = executable.get_text_bytes().1;

    let mut hash = 0u64;
    let mut fields = vec![];
    
    // TODO: handle vector
    for length in 0u64..1000 {
        let mut stack: AlignedMemory<{ HOST_ALIGN }> =
            AlignedMemory::zero_filled(config.stack_size());
        let mut heap: AlignedMemory<{ HOST_ALIGN }> = AlignedMemory::zero_filled(256 * 1024);
        let mut mem = vec![0u8; 1024 * 1024];
        mem[0..8].copy_from_slice(&ebpf::MM_INPUT_START.to_le_bytes());
        mem[8..16].copy_from_slice(&length.to_le_bytes());

        let mem_region = MemoryRegion::new_writable(&mut mem, ebpf::MM_INPUT_START);
        let regions: Vec<MemoryRegion> = vec![
            executable.get_ro_region(),
            MemoryRegion::new_writable_gapped(
                stack.as_slice_mut(),
                ebpf::MM_STACK_START,
                if !sbpf_version.dynamic_stack_frames() && config.enable_stack_frame_gaps {
                    config.stack_frame_size as u64
                } else {
                    0
                },
            ),
            MemoryRegion::new_writable(heap.as_slice_mut(), ebpf::MM_HEAP_START),
            mem_region,
        ];

        let mut invoke_context = TestContextObject::new(1_000_000);

        let memory_mapping = MemoryMapping::new(regions, &config, sbpf_version).unwrap();
        let mut vm = EbpfVm::new(
            executable.get_loader().clone(),
            executable.get_sbpf_version(),
            &mut invoke_context,
            memory_mapping,
            stack.len(),
        );

        let initial_insn_count = vm.context_object_pointer.get_remaining();
        vm.previous_instruction_meter = initial_insn_count;

        vm.registers[5] = ebpf::MM_INPUT_START + 0x1000;
        vm.registers[11] = entrypoint as u64;

        let registers = vm.registers;
        let mut interpreter = Interpreter::new(&mut vm, &executable, registers);
        while interpreter.step() {}
        interpreter.reg[11] += 1;
        while interpreter.step() {
            let pc = interpreter.reg[11];
            let insn = ebpf::get_insn_unchecked(program, pc as usize);
            if insn.opc == ebpf::CALL_IMM {
                break;
            }
        }
        let new_hash = invoke_context.hash_trace_log();
        if new_hash != hash {
            hash = new_hash;
            fields.push(length);
        }
    }

    let mut args = vec![];
    for idx in 0..fields.len() - 1 {
        args.push(ArgMeta {
            name: format!("field_{}", idx),
            ty: match fields[idx + 1] - fields[idx] {
                1 => "u8".to_string(),
                2 => "u16".to_string(),
                4 => "u32".to_string(),
                8 => "u64".to_string(),
                16 => "u128".to_string(),
                32 => "pubkey".to_string(),
                x => format!("[u8; {}]", x),
            },
        });
    }
    args
}

pub fn extract_types(
    executable_data: &[u8],
    deserializers: &BTreeMap<String, usize>,
) -> Vec<IDLType> {
    let config = Config {
        enabled_sbpf_versions: SBPFVersion::V0..=SBPFVersion::V3,
        enable_instruction_tracing: true,
        ..Config::default()
    };
    let loader = BuiltinProgram::new_loader(config.clone());
    let executable =
        Executable::<TestContextObject>::from_elf(executable_data, Arc::new(loader)).unwrap();
    let sbpf_version = executable.get_sbpf_version();
    let program = executable.get_text_bytes().1;

    let mut types = vec![];

    for (account_name, &entrypoint) in deserializers {
        let mut hash = 0u64;
        let mut fields = vec![];
        
        // TODO: handle vector
        for length in 0u64..1000 {
            let mut stack: AlignedMemory<{ HOST_ALIGN }> =
                AlignedMemory::zero_filled(config.stack_size());
            let mut heap: AlignedMemory<{ HOST_ALIGN }> = AlignedMemory::zero_filled(256 * 1024);
            let mut mem = vec![0u8; 1024 * 1024];
            mem[0..8].copy_from_slice(&ebpf::MM_INPUT_START.to_le_bytes());
            mem[8..16].copy_from_slice(&length.to_le_bytes());

            let mem_region = MemoryRegion::new_writable(&mut mem, ebpf::MM_INPUT_START);
            let regions: Vec<MemoryRegion> = vec![
                executable.get_ro_region(),
                MemoryRegion::new_writable_gapped(
                    stack.as_slice_mut(),
                    ebpf::MM_STACK_START,
                    if !sbpf_version.dynamic_stack_frames() && config.enable_stack_frame_gaps {
                        config.stack_frame_size as u64
                    } else {
                        0
                    },
                ),
                MemoryRegion::new_writable(heap.as_slice_mut(), ebpf::MM_HEAP_START),
                mem_region,
            ];

            let mut invoke_context = TestContextObject::new(1_000_000);

            let memory_mapping = MemoryMapping::new(regions, &config, sbpf_version).unwrap();
            let mut vm = EbpfVm::new(
                executable.get_loader().clone(),
                executable.get_sbpf_version(),
                &mut invoke_context,
                memory_mapping,
                stack.len(),
            );

            let initial_insn_count = vm.context_object_pointer.get_remaining();
            vm.previous_instruction_meter = initial_insn_count;

            vm.registers[2] = ebpf::MM_INPUT_START;
            vm.registers[11] = entrypoint as u64;

            let registers = vm.registers;
            let mut interpreter = Interpreter::new(&mut vm, &executable, registers);
            while interpreter.step() {}
            interpreter.reg[11] += 1;
            while interpreter.step() {
                let pc = interpreter.reg[11];
                let insn = ebpf::get_insn_unchecked(program, pc as usize);
                if insn.opc == ebpf::CALL_IMM {
                    break;
                }
            }
            let new_hash = invoke_context.hash_trace_log();
            if new_hash != hash {
                hash = new_hash;
                fields.push(length);
            }
        }

        let mut args = vec![];
        for idx in 1..fields.len() - 1 {
            args.push(ArgMeta {
                name: format!("field_{}", idx - 1),
                ty: match fields[idx + 1] - fields[idx] {
                    1 => "u8".to_string(),
                    2 => "u16".to_string(),
                    4 => "u32".to_string(),
                    8 => "u64".to_string(),
                    16 => "u128".to_string(),
                    32 => "pubkey".to_string(),
                    x => format!("[u8; {}]", x),
                },
            });
        }
        types.push(IDLType {
            name: account_name.to_string(),
            ty: InnerType {
                kind: "struct".to_string(),
                fields: args,
            },
        });
    }

    types
}
