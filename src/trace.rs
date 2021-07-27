#![allow(non_upper_case_globals)]

use nix::errno::Errno;
use nix::sys::ptrace::{
    getevent as ptrace_getevent, setoptions as ptrace_setoptions, Options as PTraceOptions,
    Request as PTraceRequest,
};
use nix::sys::wait::WaitPidFlag;
use nix::unistd::Pid;

use bitflags::bitflags;
use fnv::FnvHashMap as HashMap;
use fnv::FnvHashSet as HashSet;

use fugue::bytes::{ByteCast, BE, LE};

use parking_lot::RwLock;

use std::mem::{size_of, swap, take};
use std::sync::Arc;

use thiserror::Error;

use crate::arch::{self, DebugRegisters, Registers, Word};
use crate::breakpoint::hardware as hwbp;
use crate::breakpoint::hardware::Breakpoint as HWBreakpoint;
use crate::breakpoint::software as swbp;
use crate::breakpoint::software::Breakpoint as SWBreakpoint;
use crate::breakpoint::{self, Breakpoint};
use crate::command::Command;
use crate::observer::Observer;
use crate::util::{ptrace, waitpid, AsPid};

#[derive(Debug, Error)]
pub enum Error {
    #[error("could not attach to `{0}`; {1}")]
    Attach(Pid, nix::Error),
    #[error("breakpoint: {0}")]
    Breakpoint(#[from] crate::breakpoint::hardware::Error),
    #[error("breakpoint already exists for address {0:#x}")]
    BreakpointExists(Word),
    #[error("memory read at {0:#x} failed: {1}")]
    MemoryRead(Word, nix::Error),
    #[error("memory write at {0:#x} failed: {1}")]
    MemoryWrite(Word, nix::Error),
    #[error("could not launch tracee {:?}: {1}", _0.command())]
    TraceLaunch(Command, nix::Error),
    #[error("could not set ptrace options: {0}")]
    TraceSetOptions(nix::Error),
    #[error("fatal: {0}")]
    Fatal(nix::Error),
    #[error("process `{0}` entered unexpected state")]
    UnexpectedState(Pid),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum State {
    Start,
    Stop,
    PreCall,
    PostCall,
    Signal,
    Exec,
    Step,
    Breakpoint(i32),
    SoftBreakpoint(Word),
    Detach,
}

impl Default for State {
    fn default() -> Self {
        Self::Start
    }
}

bitflags! {
    pub struct Flags: u16 {
        const Hold      = 0x01;
        const Held      = 0x02;
        const StepTrace = 0x04;
        const Release   = 0x08;
        const NoSyscall = 0x10;
    }
}

#[derive(Clone)]
pub struct Process {
    regs: Registers,
    debug_regs: DebugRegisters,

    state: State,

    status: i32,
    event: i32,
    signal: i32,
    exit_code: i32,

    flags: Flags,
    oobflags: Flags,

    pid: Pid,

    hw_breakpoints: HashMap<breakpoint::Id, HWBreakpoint>,
    hw_counter: breakpoint::Id,

    sw_breakpoints: HashMap<Word, SWBreakpoint>,
    sw_masked: HashSet<Word>,
}

impl Process {
    pub fn new(pid: Pid) -> Result<Self, Error> {
        let mut t = Self {
            regs: Registers::default(),
            debug_regs: DebugRegisters::default(),

            state: State::default(),

            flags: Flags::empty(),
            oobflags: Flags::empty(),

            pid,

            status: 0,
            event: 0,
            signal: 0,
            exit_code: 0,

            hw_breakpoints: HashMap::default(),
            hw_counter: 0,

            sw_breakpoints: HashMap::default(),
            sw_masked: HashSet::default(),
        };

        t.debug_regs.initialise(pid).map_err(Error::Fatal)?;

        ptrace_setoptions(
            pid,
            PTraceOptions::PTRACE_O_TRACEFORK
                | PTraceOptions::PTRACE_O_TRACEVFORK
                | PTraceOptions::PTRACE_O_TRACECLONE
                | PTraceOptions::PTRACE_O_TRACEEXEC
                | PTraceOptions::PTRACE_O_TRACEEXIT
                | PTraceOptions::PTRACE_O_TRACESYSGOOD,
        )
        .map_err(Error::TraceSetOptions)?;

        Ok(t)
    }

    pub fn pid(&self) -> Pid {
        self.pid
    }

    pub fn registers(&self) -> &arch::RegisterSet {
        self.regs.current()
    }

    pub fn registers_mut(&mut self) -> &mut arch::RegisterSet {
        self.regs.current_mut()
    }

    #[cfg(target_arch = "x86")]
    pub fn program_counter(&self) -> i32 {
        self.registers().eip
    }

    #[cfg(target_arch = "x86_64")]
    pub fn program_counter(&self) -> u64 {
        self.registers().rip
    }

    #[cfg(target_arch = "x86")]
    pub fn program_counter_mut(&mut self) -> &mut i32 {
        &mut self.registers_mut().eip
    }

    #[cfg(target_arch = "x86_64")]
    pub fn program_counter_mut(&mut self) -> &mut u64 {
        &mut self.registers_mut().rip
    }

    fn event(&self) -> Option<i32> {
        if self.event == 0 {
            None
        } else {
            Some(self.event)
        }
    }

    pub fn is_event(&self, event: i32) -> bool {
        self.event == event
    }

    pub fn is_event_exit(&self) -> bool {
        self.is_event(libc::PTRACE_EVENT_EXIT)
    }

    pub fn is_event_exec(&self) -> bool {
        self.is_event(libc::PTRACE_EVENT_EXEC)
    }

    pub fn is_event_stop(&self) -> bool {
        self.is_event(libc::PTRACE_EVENT_STOP)
    }

    pub fn has_event(&self) -> bool {
        self.event != 0
    }

    fn signal(&self) -> Option<i32> {
        if self.signal == 0 {
            None
        } else {
            Some(self.signal)
        }
    }

    pub fn is_signal(&self, signal: i32) -> bool {
        self.signal == signal
    }

    pub fn has_signal(&self) -> bool {
        self.signal != 0
    }

    pub fn is_signal_trap(&self) -> bool {
        self.is_signal(libc::SIGTRAP)
    }

    pub fn is_signal_trap_call(&self) -> bool {
        self.is_signal(0x85)
    }

    fn update_status(&mut self, status: i32) {
        self.status = status;
        self.signal = status.checked_shr(8).unwrap_or(0) & 0xff;
        self.event = status.checked_shr(16).unwrap_or(0) & 0xff;
    }

    fn clear_signal(&mut self) {
        self.signal = 0;
    }

    #[cfg(target_pointer_width = "32")]
    pub fn event_message(&self) -> Result<i32, Error> {
        ptrace_getevent(self.pid).map_err(Error::Fatal)
    }

    #[cfg(target_pointer_width = "64")]
    pub fn event_message(&self) -> Result<i64, Error> {
        ptrace_getevent(self.pid).map_err(Error::Fatal)
    }

    pub fn step_trace(&mut self, val: bool) {
        if val {
            self.flags |= Flags::StepTrace;
        } else {
            self.flags &= !Flags::StepTrace;
        }

        self.trap(val);
    }

    pub fn step_tracing(&self) -> bool {
        self.flags.intersects(Flags::StepTrace)
    }

    pub fn syscall_trace(&mut self, val: bool) {
        if val {
            self.flags |= Flags::NoSyscall;
        } else {
            self.flags &= !Flags::NoSyscall;
        }
    }

    pub fn syscall_tracing(&self) -> bool {
        !self.flags.intersects(Flags::NoSyscall)
    }

    fn next_is_syscall(&self) -> bool {
        let mut next = [0u8; 32];
        #[cfg(target_arch = "x86")]
        let patterns: &[&[u8]] = &[
            &[0xcd, 0x80],                               // int 0x80
            &[0x0f, 0x34],                               // sysenter
            &[0x65, 0xff, 0x15, 0x10, 0x00, 0x00, 0x00], // call dword ptr gs:[0x10]
        ];
        #[cfg(target_arch = "x86_64")]
        let patterns: &[&[u8]] = &[
            &[0x0f, 0x05], // syscall
            &[0x0f, 0x34], // sysenter
        ];

        let address = self.program_counter() as _;
        patterns.iter().any(|pat| {
            let insn = &mut next[..pat.len()];
            matches!(self.read_memory(address, insn), Ok(_) if insn == &pat[..])
        })
    }

    pub fn try_continue(&mut self) -> Result<(), Error> {
        if self.flags.intersects(Flags::Hold) {
            self.flags |= Flags::Held;
        }

        let cont = if self.state == State::Detach {
            self.detach_cleanup();
            PTraceRequest::PTRACE_DETACH
        } else if !self.syscall_tracing() || (self.syscall_tracing() && self.step_tracing()) {
            PTraceRequest::PTRACE_CONT
        } else {
            PTraceRequest::PTRACE_SYSCALL
        };

        // Try to set BPs that got activated in observers
        self.try_activate_hw_breakpoints().ok();
        self.try_activate_sw_breakpoints().ok();

        if !self.sw_masked.is_empty() && cont == PTraceRequest::PTRACE_SYSCALL {
            // we have to restore some software BPs
            // if we are step tracing, then the BP will get restored on the
            // next event anyway.
            //
            // if we are in syscall tracing, and the next instruction is not a
            // syscall, then we set a trap so we can perform the restore
            if !self.next_is_syscall() {
                self.trap(true);
            }
        }

        self.write_modified_registers()?;

        ptrace(cont, self.pid, 0, self.signal()).map_err(Error::Fatal)?;

        if self.state == State::Stop {
            waitpid(self.pid, Some(WaitPidFlag::__WALL)).map_err(Error::Fatal)?;
        }

        if self.flags.intersects(Flags::Held) {
            self.flags &= !Flags::Held;
        }

        Ok(())
    }

    pub fn detach(&mut self) -> Result<(), Error> {
        self.oobflags |= Flags::Release;

        Errno::clear();

        let err = ptrace(PTraceRequest::PTRACE_INTERRUPT, self.pid, 0, 0);

        if err.is_err() && Errno::last() != Errno::EIO {
            return err.map(|_| ()).map_err(Error::Fatal);
        }

        Ok(())
    }

    fn update_process_info(&mut self) -> Result<(), Error> {
        self.update_registers()?;

        if self.step_tracing() ^ self.is_trapped() {
            self.trap(self.step_tracing());
        }

        Ok(())
    }

    fn update_registers(&mut self) -> Result<(), Error> {
        self.regs.update(self.pid).map_err(Error::Fatal)
    }

    pub fn write_modified_registers(&mut self) -> Result<(), Error> {
        self.regs.write_modified(self.pid).map_err(Error::Fatal)?;
        self.debug_regs
            .write_modified(self.pid)
            .map_err(Error::Fatal)?;
        Ok(())
    }

    fn detach_cleanup(&mut self) {
        self.step_trace(false);
        self.debug_regs.clear();
    }

    #[cfg(target_arch = "x86")]
    pub fn syscall(&self) -> i32 {
        if self.step_tracing() {
            self.regs.current().eax
        } else {
            self.regs.current().orig_eax
        }
    }

    #[cfg(target_arch = "x86_64")]
    pub fn syscall(&self) -> u64 {
        if self.step_tracing() {
            self.regs.current().rax
        } else {
            self.regs.current().orig_rax
        }
    }

    #[cfg(target_arch = "x86")]
    pub fn syscall_ret(&self) -> i32 {
        self.regs.current().eax
    }

    #[cfg(target_arch = "x86_64")]
    pub fn syscall_ret(&self) -> u64 {
        self.regs.current().rax
    }

    #[cfg(target_arch = "x86_64")]
    pub fn syscall_ret_mut(&mut self) -> &mut u64 {
        &mut self.regs.current_mut().rax
    }

    #[cfg(target_arch = "x86")]
    pub fn syscall_arg(&self, n: usize) -> Option<i32> {
        match n {
            0 => Some(self.regs.current().ebx),
            1 => Some(self.regs.current().ecx),
            2 => Some(self.regs.current().edx),
            3 => Some(self.regs.current().esi),
            4 => Some(self.regs.current().edi),
            5 => Some(self.regs.current().ebp),
            _ => None,
        }
    }

    #[cfg(target_arch = "x86_64")]
    pub fn syscall_arg(&self, n: usize) -> Option<u64> {
        match n {
            0 => Some(self.regs.current().rdi),
            1 => Some(self.regs.current().rsi),
            2 => Some(self.regs.current().rdx),
            3 => Some(self.regs.current().r10),
            4 => Some(self.regs.current().r8),
            5 => Some(self.regs.current().r9),
            _ => None,
        }
    }

    #[cfg(target_arch = "x86_64")]
    pub fn syscall_arg_mut(&mut self, n: usize) -> Option<&mut u64> {
        match n {
            0 => Some(&mut self.regs.current_mut().rdi),
            1 => Some(&mut self.regs.current_mut().rsi),
            2 => Some(&mut self.regs.current_mut().rdx),
            3 => Some(&mut self.regs.current_mut().r10),
            4 => Some(&mut self.regs.current_mut().r8),
            5 => Some(&mut self.regs.current_mut().r9),
            _ => None,
        }
    }

    pub fn read_memory_value<T: ByteCast>(&mut self, address: Word) -> Result<T, Error> {
        let mut buf = [0u8; 16];
        self.read_memory(address, &mut buf[..T::SIZEOF])?;
        Ok(if cfg!(target_endian = "big") {
            T::from_bytes::<BE>(&buf[..T::SIZEOF])
        } else {
            T::from_bytes::<LE>(&buf[..T::SIZEOF])
        })
    }

    pub fn read_memory(&self, address: Word, buffer: &mut [u8]) -> Result<(), Error> {
        let mut addr = address;
        let mut data = [0u8; size_of::<Word>()];
        let mut to_read = buffer.len();
        let mut offset = size_of::<Word>();
        let mut bufpos = 0;

        while to_read != 0 {
            if offset == size_of::<Word>() {
                offset = addr as usize & (size_of::<Word>() - 1);
                addr -= offset as Word;
                let d = ptrace(PTraceRequest::PTRACE_PEEKTEXT, self.pid, addr, 0)
                    .map_err(|e| Error::MemoryRead(addr as _, e))?;
                data.copy_from_slice(&d.to_ne_bytes()[..]);
                addr += size_of::<Word>() as Word;
            }

            buffer[bufpos] = data[offset];

            bufpos += 1;
            offset += 1;
            to_read -= 1;
        }

        Ok(())
    }

    pub fn write_memory_value<T: ByteCast>(&mut self, address: Word, value: T) -> Result<(), Error> {
        let mut buf = [0u8; 16];
        if cfg!(target_endian = "big") {
            value.into_bytes::<BE>(&mut buf);
        } else {
            value.into_bytes::<LE>(&mut buf);
        }
        self.write_memory(address, &buf)
    }

    pub fn write_memory(&mut self, address: Word, buffer: &[u8]) -> Result<(), Error> {
        let mut addr = address;
        let mut data = [0u8; size_of::<Word>()];
        let mut to_write = buffer.len();
        let mut buf_pos = 0;

        let mut align_off = addr as usize % size_of::<Word>();
        if align_off != 0 {
            addr -= align_off as Word;
        }

        while to_write != 0 {
            if align_off != 0 || to_write < size_of::<Word>() {
                let d = ptrace(PTraceRequest::PTRACE_PEEKDATA, self.pid, addr, 0)
                    .map_err(|e| Error::MemoryRead(addr as _, e))?;
                data.copy_from_slice(&d.to_ne_bytes()[..]);
            }

            let size = (size_of::<Word>() - align_off).min(to_write);
            data[align_off..size].copy_from_slice(&buffer[buf_pos..buf_pos + size]);

            ptrace(
                PTraceRequest::PTRACE_POKEDATA,
                self.pid,
                addr,
                Word::from_ne_bytes(data),
            )
            .map_err(|e| Error::MemoryWrite(addr as _, e))?;

            to_write -= to_write.min(size);
            buf_pos += size;
            addr += size_of::<Word>() as Word;
            align_off = 0;
        }

        Ok(())
    }

    pub fn add_hardware_breakpoint(
        &mut self,
        address: Word,
        size: usize,
        trigger: hwbp::Trigger,
        flags: hwbp::Flags,
    ) -> Result<breakpoint::Id, Error> {
        let mut bp = HWBreakpoint::new(address, size, trigger, flags)?;
        let id = self.hw_counter;

        self.try_activate_hw_breakpoint(&mut bp).ok();

        self.hw_counter += 1;
        self.hw_breakpoints.insert(id, bp);

        Ok(id)
    }

    pub fn enable_hardware_breakpoint(&mut self, id: breakpoint::Id) -> Result<(), Error> {
        if let Some(bp) = self.hw_breakpoints.get_mut(&id) {
            if !bp.disabled() {
                return Ok(());
            }

            bp.enable();
            let index = self
                .debug_regs
                .set_watchpoint(bp.address(), bp.trigger(), bp.size())?;

            bp.update_index(index);
        }
        Ok(())
    }

    pub fn disable_hardware_breakpoint(&mut self, id: breakpoint::Id) -> Result<(), Error> {
        if let Some(bp) = self.hw_breakpoints.get_mut(&id) {
            if bp.disabled() {
                return Ok(());
            }

            bp.disable();

            if let Some(index) = bp.index() {
                self.debug_regs.unset_watchpoint(index);
                bp.clear_index();
            }
        }
        Ok(())
    }

    pub fn remove_hardware_breakpoint(&mut self, id: breakpoint::Id) -> Result<(), Error> {
        self.disable_hardware_breakpoint(id)?;
        self.hw_breakpoints.remove(&id);
        Ok(())
    }

    pub fn add_software_breakpoint(
        &mut self,
        address: Word,
        kind: swbp::Kind,
        flags: swbp::Flags,
    ) -> Result<(), Error> {
        if self.sw_breakpoints.contains_key(&(address as _)) {
            return Err(Error::BreakpointExists(address as _));
        }

        let mut bp = SWBreakpoint::new(address as _, kind, flags);

        self.try_activate_sw_breakpoint(&mut bp).ok();

        self.sw_breakpoints.insert(address as _, bp);

        Ok(())
    }

    pub fn enable_software_breakpoint(&mut self, address: Word) -> Result<(), Error> {
        let mut bps = take(&mut self.sw_breakpoints);
        let result = (|| if let Some(bp) = bps.get_mut(&address) {
            if !bp.disabled() {
                return Ok(())
            }

            bp.enable();
            if self.sw_masked.contains(&address) {
                return Ok(());
            }

            let mut current = [0u8; size_of::<Word>()];
            self.read_memory(bp.address() as _, &mut current[..])?;

            let current_val = Word::from_ne_bytes(current);

            if !bp.is_set(current_val) {
                *bp.original_mut() = Some(current_val);

                self.write_memory(
                    bp.address() as _,
                    &bp.replacement().unwrap().to_ne_bytes()[..],
                )?;
            }

            Ok(())
        } else {
            Ok(())
        })();

        self.sw_breakpoints = bps;
        result
    }

    pub fn disable_software_breakpoint(&mut self, address: Word) -> Result<(), Error> {
        let mut bps = take(&mut self.sw_breakpoints);
        let result = (|| if let Some(bp) = bps.get_mut(&address) {
            if bp.disabled() {
                return Ok(());
            }

            bp.disable();
            bp.unmask();

            self.sw_masked.remove(&address);

            let mut current = [0u8; size_of::<Word>()];
            self.read_memory(bp.address() as _, &mut current[..])?;

            let current_val = Word::from_ne_bytes(current);

            if bp.is_set(current_val) {
                self.write_memory(
                    bp.address() as _,
                    &bp.original().unwrap().to_ne_bytes()[..],
                )?;
            }

            Ok(())
        } else {
            Ok(())
        })();
        self.sw_breakpoints = bps;
        result
    }

    pub fn remove_software_breakpoint(&mut self, address: Word) -> Result<(), Error> {
        self.disable_software_breakpoint(address)?;
        self.sw_breakpoints.remove(&address);
        Ok(())
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn try_activate_sw_breakpoint(&mut self, breakpoint: &mut SWBreakpoint) -> Result<(), Error> {
        if breakpoint.disabled() {
            return Ok(());
        }

        if breakpoint.masked() {
            breakpoint.unmask();
            return Ok(());
        }

        let mut current = [0u8; size_of::<Word>()];
        self.read_memory(breakpoint.address() as _, &mut current[..])?;

        let current_val = Word::from_ne_bytes(current);

        if !breakpoint.is_set(current_val) {
            *breakpoint.original_mut() = Some(current_val);

            self.write_memory(
                breakpoint.address() as _,
                &breakpoint.replacement().unwrap().to_ne_bytes()[..],
            )?;
        }

        self.sw_masked.remove(&breakpoint.address());

        Ok(())
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn soft_breakpoint_triggered(&mut self) -> Result<bool, Error> {
        let bp_address = self.program_counter() as Word - 1; // as 0xcc
        if matches!(self.sw_breakpoints.get(&bp_address), Some(bp) if self.is_soft_breakpoint_active(bp))
        {
            let bp = self.sw_breakpoints.get_mut(&bp_address).unwrap();
            if bp.update_hit() {
                // masked
                self.sw_masked.insert(bp_address);
            }

            let orig = bp.original().unwrap();

            // restore
            *self.program_counter_mut() = bp_address as _;
            self.write_memory(bp_address as _, &orig.to_ne_bytes())?;

            Ok(true)
        } else {
            Ok(false)
        }
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn is_soft_breakpoint_active(&self, breakpoint: &SWBreakpoint) -> bool {
        if breakpoint.disabled() || breakpoint.masked() {
            return false;
        }

        let mut current = [0u8; size_of::<usize>()];
        if self
            .read_memory(breakpoint.address() as _, &mut current[..])
            .is_err()
        {
            return false;
        }

        let current_val = Word::from_ne_bytes(current);
        breakpoint.is_set(current_val)
    }

    fn try_activate_sw_breakpoints(&mut self) -> Result<(), Error> {
        let mut tbreakpoints = take(&mut self.sw_breakpoints);

        let _result = tbreakpoints
            .iter_mut()
            .for_each(|(_, bp)| { self.try_activate_sw_breakpoint(bp).ok(); });

        self.sw_breakpoints = tbreakpoints;

        Ok(())
    }

    fn try_activate_hw_breakpoint(&mut self, breakpoint: &mut HWBreakpoint) -> Result<(), Error> {
        if breakpoint.disabled() || breakpoint.index().is_some() {
            return Ok(());
        }

        let index = self.debug_regs.set_watchpoint(
            breakpoint.address(),
            breakpoint.trigger(),
            breakpoint.size(),
        )?;

        breakpoint.update_index(index);

        Ok(())
    }

    fn try_activate_hw_breakpoints(&mut self) -> Result<(), Error> {
        let mut tbreakpoints = take(&mut self.hw_breakpoints);

        let _result = tbreakpoints
            .iter_mut()
            .for_each(|(_, bp)| { self.try_activate_hw_breakpoint(bp).ok(); });

        self.hw_breakpoints = tbreakpoints;

        Ok(())
    }

    fn update_breakpoints(&mut self, parent: Option<&mut Self>) -> Result<(), Error> {
        match (self.state, parent) {
            (State::Start, Some(parent)) => {
                self.hw_breakpoints = parent
                    .hw_breakpoints
                    .iter()
                    .filter_map(|(id, bp)| {
                        if bp.copy_on_fork() {
                            let mut nbp = bp.clone();
                            nbp.clear_index();
                            Some((*id, nbp))
                        } else {
                            None
                        }
                    })
                    .collect();
                self.sw_breakpoints = parent
                    .sw_breakpoints
                    .iter()
                    .filter_map(|(v, bp)| {
                        if bp.copy_on_fork() {
                            let mut nbp = bp.clone();
                            nbp.unmask();
                            Some((*v, nbp))
                        } else {
                            None
                        }
                    })
                    .collect();
                self.try_activate_hw_breakpoints()?;
                self.try_activate_sw_breakpoints()
            }
            (State::Exec, Some(parent)) => {
                self.hw_breakpoints = parent
                    .hw_breakpoints
                    .iter()
                    .filter_map(|(id, bp)| {
                        if bp.copy_on_exec() {
                            let mut nbp = bp.clone();
                            nbp.clear_index();
                            Some((*id, nbp))
                        } else {
                            None
                        }
                    })
                    .collect();
                self.sw_breakpoints = parent
                    .sw_breakpoints
                    .iter()
                    .filter_map(|(v, bp)| {
                        if bp.copy_on_exec() {
                            let mut nbp = bp.clone();
                            nbp.unmask();
                            Some((*v, nbp))
                        } else {
                            None
                        }
                    })
                    .collect();
                self.try_activate_hw_breakpoints()?;
                self.try_activate_sw_breakpoints()
            }
            (State::PostCall, _) => {
                let sys = self.syscall();
                let arg = self.syscall_arg(3);
                if sys == arch::SYS_MMAP
                    && matches!(arg, Some(v) if (v as i32 & libc::MAP_ANONYMOUS) != 0)
                {
                    self.try_activate_hw_breakpoints()?;
                    self.try_activate_sw_breakpoints()?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn trap(&mut self, val: bool) {
        if val {
            self.regs.current_mut().eflags |= arch::TRAP_FLAG;
        } else {
            self.regs.current_mut().eflags &= !arch::TRAP_FLAG;
        }
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn is_trapped(&self) -> bool {
        (self.regs.current().eflags & arch::TRAP_FLAG) != 0
    }
}

pub struct Tracer {
    processes: HashMap<Pid, Arc<RwLock<Process>>>,
    observers: Vec<Box<dyn Observer>>,
}

impl Tracer {
    pub fn new() -> Self {
        Self {
            processes: HashMap::default(),
            observers: Vec::new(),
        }
    }

    pub fn add_observer<O: Observer>(&mut self, observer: O) {
        self.observers.push(Box::new(observer))
    }

    pub fn detach_all(&mut self) -> Result<(), Error> {
        for p in self.processes.values_mut() {
            p.write().detach()?;
        }
        Ok(())
    }

    pub fn detach_on_failure(&mut self) {
        for (pid, p) in self.processes.drain() {
            let mut t = p.write();

            ptrace(
                if t.flags.intersects(Flags::NoSyscall) {
                    PTraceRequest::PTRACE_CONT
                } else {
                    PTraceRequest::PTRACE_SYSCALL
                },
                pid,
                0,
                0,
            )
            .ok();

            ptrace(PTraceRequest::PTRACE_INTERRUPT, pid, 0, 0).ok();

            let status = waitpid(pid, Some(WaitPidFlag::__WALL))
                .map(|v| v.1)
                .unwrap_or(0);

            t.update_status(status);
            if t.is_signal_trap() || t.is_signal_trap_call() {
                t.clear_signal();
            }

            t.step_trace(false);
            t.debug_regs.clear();
            t.write_modified_registers().ok();

            ptrace(PTraceRequest::PTRACE_DETACH, pid, 0, t.signal).ok();
        }
    }

    fn despatch_observers(
        &mut self,
        t: &mut Process,
        parent: Option<&mut Process>,
    ) -> Result<(), Error> {
        match t.state {
            State::Start => self
                .observers
                .iter_mut()
                .try_for_each(|o| o.start(t, &parent)),
            State::Stop => self.observers.iter_mut().try_for_each(|o| o.stop(t)),
            State::Exec => self.observers.iter_mut().try_for_each(|o| o.exec(t)),
            State::Step => self.observers.iter_mut().try_for_each(|o| o.step(t)),
            State::Breakpoint(dr_index) => {
                if let Some(bp) = t
                    .hw_breakpoints
                    .iter()
                    .find(|(_, bp)| bp.index() == Some(dr_index))
                {
                    let bp = Breakpoint::Hardware(bp.1.clone());
                    self.observers
                        .iter_mut()
                        .try_for_each(|o| o.breakpoint(t, &bp))
                } else {
                    Ok(())
                }
            }
            State::SoftBreakpoint(ref addr) => {
                let bp = Breakpoint::Software(t.sw_breakpoints[addr].clone());
                self.observers
                    .iter_mut()
                    .try_for_each(|o| o.breakpoint(t, &bp))
            }
            State::Detach => self.observers.iter_mut().try_for_each(|o| o.detach(t)),
            State::Signal => self.observers.iter_mut().try_for_each(|o| o.signal(t)),
            State::PreCall => self.observers.iter_mut().try_for_each(|o| o.pre_call(t)),
            State::PostCall => self.observers.iter_mut().try_for_each(|o| o.post_call(t)),
        }
    }

    pub fn trace_attach<P: AsPid>(&mut self, pid: P) -> Result<(), Error> {
        let pid = pid.as_pid();
        ptrace(PTraceRequest::PTRACE_SEIZE, pid, 0, 0).map_err(|e| Error::Attach(pid, e))?;
        ptrace(PTraceRequest::PTRACE_INTERRUPT, pid, 0, 0).map_err(|e| Error::Attach(pid, e))?;
        self.trace(pid)
    }

    pub fn trace_launch(&mut self, command: &Command) -> Result<(), Error> {
        let pid = command
            .launch()
            .map_err(|e| Error::TraceLaunch(command.clone(), e))?;
        self.trace(pid)
    }

    pub fn trace<P: AsPid>(&mut self, pid: P) -> Result<(), Error> {
        let pid = pid.as_pid();
        let mut new_pid = Some(pid);
        let mut parent = None;

        self.observers.iter_mut().try_for_each(|o| o.init())?;

        while new_pid.is_some() || !self.processes.is_empty() {
            let mut tl = self.wait_for_event(new_pid.unwrap_or(Pid::from_raw(-1)))?;
            {
                let mut t = tl.write();
                let is_trap = t.event().is_none() && t.is_signal_trap();

                if t.is_signal_trap() || t.is_signal_trap_call() {
                    t.clear_signal();
                }

                if new_pid.is_some() {
                    t.state = State::Start;
                    new_pid = None;
                } else if t.soft_breakpoint_triggered()? {
                    t.state = State::SoftBreakpoint(t.program_counter() as _);
                } else if is_trap {
                    let tpid = t.pid;
                    t.state = if let Some(id) = t
                        .debug_regs
                        .breakpoints_triggered(tpid)
                        .map_err(Error::Fatal)?
                    {
                        // HW BP hit
                        State::Breakpoint(id)
                    } else if t.step_tracing() && t.syscall_tracing() && t.next_is_syscall() {
                        //if t.state == State::PreCall {
                        //    State::PostCall
                        //} else {
                        State::PreCall
                        //}
                    } else if t.state == State::PreCall {
                        State::PostCall
                    } else {
                        State::Step
                    }
                } else if t.is_event_exit() {
                    t.exit_code = t.event_message()? as i32;
                    t.state = State::Stop;
                } else if t.is_event_exec() {
                    let tpid = t.pid;
                    t.state = State::Exec;
                    t.debug_regs.initialise(tpid).map_err(Error::Fatal)?;
                } else if t.is_event_stop() {
                    if !t.oobflags.intersects(Flags::Release) {
                        t.try_continue()?;
                        continue;
                    }
                    t.state = State::Detach;
                } else if t.has_event() {
                    let npid = Pid::from_raw(t.event_message()? as i32);
                    drop(t);
                    if let Some(pt) = self.processes.get(&npid) {
                        let mut nparent = pt.clone();
                        swap(&mut tl, &mut nparent);

                        tl.write().state = State::Start;

                        parent = Some(nparent);
                        new_pid = None;
                    } else {
                        parent = Some(tl);
                        new_pid = Some(npid);
                        continue;
                    }
                } else if t.has_signal() {
                    t.state = State::Signal;
                } else if matches!(t.state, State::PreCall | State::Exec) {
                    t.state = State::PostCall;
                } else {
                    t.state = State::PreCall;
                }
            }

            let mut t = tl.write();

            if let Some(p) = parent.take() {
                let mut p = p.write();
                t.update_breakpoints(Some(&mut *p))?;
                self.despatch_observers(&mut *t, Some(&mut *p))?;
                p.try_continue()?;
            } else {
                t.update_breakpoints(None)?;
                self.despatch_observers(&mut *t, None)?;
            }

            if t.state != State::Detach && t.oobflags.intersects(Flags::Release) {
                t.state = State::Detach;
                self.despatch_observers(&mut *t, None)?;
            }

            t.try_continue()?;

            if t.state == State::Stop || t.state == State::Detach {
                self.processes.remove(&t.pid);
            }
        }

        self.observers.iter_mut().try_for_each(|o| o.fini())?;

        Ok(())
    }

    fn wait_for_event(&mut self, pid_select: Pid) -> Result<Arc<RwLock<Process>>, Error> {
        loop {
            let (wstatus, status) =
                waitpid(pid_select, Some(WaitPidFlag::__WALL)).map_err(Error::Fatal)?;

            if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) || !libc::WIFSTOPPED(status) {
                return Err(Error::UnexpectedState(pid_select));
            }

            let pid = wstatus.pid().unwrap();

            let existing = self.processes.contains_key(&pid);
            let ok = if !existing {
                let t = Process::new(pid)?;
                self.processes.insert(pid, Arc::new(RwLock::new(t)));
                pid == pid_select
            } else {
                true
            };

            let t = self.processes.get_mut(&pid).unwrap();

            t.write().update_status(status);
            t.write().update_process_info()?;

            if ok {
                return Ok(self.processes[&pid].clone());
            }
        }
    }
}
