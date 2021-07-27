#[cfg(target_pointer_width = "64")]
pub type Word = u64;
#[cfg(target_pointer_width = "32")]
pub type Word = u32;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod x86 {
    use crate::breakpoint::hardware::{self as breakpoint, Trigger};
    use crate::util::ptrace;
    use nix::sys::ptrace::Request;
    use nix::unistd::Pid;
    use std::ops::{Deref, DerefMut};

    use super::Word;

    pub const MAX_BREAKPOINTS: usize = 4;

    pub const DEBUG_STATUS_REG: usize = 6;
    pub const DEBUG_CONTROL_REG: usize = 7;

    #[cfg(target_arch = "x86")]
    pub const PIE_BASE: Word = 0x56555000; //0x400000;
    #[cfg(target_arch = "x86_64")]
    pub const PIE_BASE: Word = 0x555555554000;

    #[cfg(target_arch = "x86")]
    pub const TRAP_FLAG: i32 = 0x100;
    #[cfg(target_arch = "x86_64")]
    pub const TRAP_FLAG: u64 = 0x100;

    #[cfg(target_arch = "x86")]
    pub const SYS_MMAP: i32 = libc::SYS_mmap2;
    #[cfg(target_arch = "x86_64")]
    pub const SYS_MMAP: u64 = libc::SYS_mmap as u64;

    const fn dr7_enable_field_shift(i: usize) -> u32 {
        i.wrapping_mul(2) as u32
    }

    const fn dr7_kind_field_shift(i: usize) -> u32 {
        i.wrapping_mul(4).wrapping_add(16) as u32
    }

    const fn dr7_len_field_shift(i: usize) -> u32 {
        i.wrapping_mul(4).wrapping_add(18) as u32
    }

    #[inline(always)]
    fn dr7_breakpoint_enabled(i: usize) -> Word {
        (1 as Word).checked_shl(dr7_enable_field_shift(i)).unwrap_or(0)
    }

    #[inline(always)]
    fn dr7_kind_field(i: usize, kind: u8) -> Word {
        (kind as Word)
            .checked_shl(dr7_kind_field_shift(i))
            .unwrap_or(0)
    }

    #[inline(always)]
    fn dr7_len_field(i: usize, len: u8) -> Word {
        (len as Word)
            .checked_shl(dr7_len_field_shift(i))
            .unwrap_or(0)
    }

    pub(crate) fn breakpoint_type(trigger: Trigger) -> Result<u8, breakpoint::Error> {
        if trigger.intersects(Trigger::Execute) && trigger != Trigger::Execute {
            Err(breakpoint::Error::InvalidTrigger(trigger))
        } else if trigger == Trigger::Execute {
            Ok(0)
        } else if (trigger & !Trigger::Write) == Trigger::Read {
            Ok(3)
        } else if trigger == Trigger::Write {
            Ok(1)
        } else {
            Err(breakpoint::Error::InvalidTrigger(trigger))
        }
    }

    fn debug_offset(id: usize) -> Word {
        unsafe {
            let ptr = std::ptr::null() as *const libc::user;
            &(*ptr).u_debugreg[id] as *const _ as Word // *mut c_void
        }
    }

    pub(crate) fn breakpoint_len_field(size: usize) -> Result<u8, breakpoint::Error> {
        match size {
            1 => Ok(0),
            2 => Ok(1),
            4 => Ok(3),
            8 => Ok(2),
            _ => Err(breakpoint::Error::InvalidSize(size)),
        }
    }

    #[derive(Debug, Default, Clone)]
    #[repr(C)]
    pub struct DebugRegisterSet {
        hardware: [Word; MAX_BREAKPOINTS],
        mapping: [i32; MAX_BREAKPOINTS],
        kind: [u8; MAX_BREAKPOINTS],
        len: [u8; MAX_BREAKPOINTS],
        status: Word,
        control: Word,
    }

    #[derive(Debug, Default, Clone)]
    #[repr(C)]
    pub struct DebugRegisters {
        regs: DebugRegisterSet,
        orig: DebugRegisterSet,
    }

    impl DebugRegisters {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn initialise(&mut self, pid: Pid) -> nix::Result<()> {
            for i in 0..MAX_BREAKPOINTS {
                self.regs.hardware[i] = 0;
                self.orig.hardware[i] = 0;

                Self::write_register(pid, i, 0)?;

                self.regs.mapping[i] = -1;
            }

            self.regs.status = 0;
            self.orig.status = 0;
            Self::write_register(pid, DEBUG_STATUS_REG, 0)?;

            self.regs.control = 0;
            self.orig.control = 0;
            Self::write_register(pid, DEBUG_CONTROL_REG, 0)?;

            Ok(())
        }

        fn compact(&mut self) {
            let mut incr = 0;
            let mut decr = MAX_BREAKPOINTS - 1;

            while decr > incr {
                if self.regs.mapping[incr] != -1 {
                    incr += 1;
                } else if self.regs.mapping[decr] == -1 {
                    decr -= 1;
                } else {
                    self.regs.hardware[incr] = self.regs.hardware[decr];
                    self.regs.mapping[incr] = self.regs.mapping[decr];
                    self.regs.kind[incr] = self.regs.kind[decr];
                    self.regs.len[incr] = self.regs.len[decr];

                    self.regs.mapping[decr] = -1;
                }
            }

            let mut control = 0;
            for i in 0..MAX_BREAKPOINTS {
                if self.regs.mapping[i] != -1 {
                    control |= dr7_breakpoint_enabled(i)
                        | dr7_kind_field(i, self.regs.kind[i])
                        | dr7_len_field(i, self.regs.len[i])
                } else {
                    self.regs.hardware[i] = self.orig.hardware[i];
                }
            }

            self.regs.control = control;
        }

        pub(crate) fn clear(&mut self) {
            self.regs.status = 0;
            for i in 0..MAX_BREAKPOINTS {
                self.regs.mapping[i] = -1;
            }
        }

        pub fn write_modified(&mut self, pid: Pid) -> nix::Result<()> {
            self.compact();

            if self.regs.status != self.orig.status {
                self.orig.status = self.regs.status;
                Self::write_register(pid, DEBUG_STATUS_REG, self.regs.status)?;
            }

            if self.regs.control != self.orig.control {
                self.orig.control = self.regs.control;
                Self::write_register(pid, DEBUG_CONTROL_REG, self.regs.control)?;
            }

            for i in 0..MAX_BREAKPOINTS {
                if self.regs.hardware[i] != self.orig.hardware[i] {
                    self.orig.hardware[i] = self.regs.hardware[i];
                    Self::write_register(pid, i, self.regs.hardware[i])?;
                }
            }

            Ok(())
        }

        pub fn breakpoints_enabled(&self) -> bool {
            !(self.regs.control != 0)
        }

        pub fn breakpoints_triggered(&mut self, pid: Pid) -> nix::Result<Option<i32>> {
            if !self.breakpoints_enabled() {
                return Ok(None);
            }

            let status = Self::read_register(pid, DEBUG_STATUS_REG)?;
            self.regs.status = 0;
            self.orig.status = status;

            let triggered = status & 0xf;
            if triggered != 0 {
                Ok(Some(4 - triggered.leading_zeros() as i32))
            } else {
                Ok(None)
            }
        }

        pub fn last_breakpoint_triggered(&self) -> Option<i32> {
            let triggered = self.orig.status & 0xf;
            if triggered != 0 {
                Some(4 - triggered.leading_zeros() as i32)
            } else {
                None
            }
        }

        fn free_slot(&self) -> Option<usize> {
            self.regs.mapping.iter()
                .enumerate()
                .find_map(|(i, v)| if *v != -1 { Some(i) } else { None })
        }

        fn free_id(&self) -> Option<i32> {
            for cur in 0..(MAX_BREAKPOINTS as i32) {
                for i in 0..=MAX_BREAKPOINTS {
                    if i == MAX_BREAKPOINTS {
                        return Some(cur)
                    }
                    if self.regs.mapping[i] == cur {
                        break
                    }
                }
            }
            None
        }

        pub fn set_watchpoint(&mut self, address: Word, trigger: Trigger, size: usize) -> Result<i32, breakpoint::Error> {
            let slot = self.free_slot().ok_or_else(|| breakpoint::Error::NoFreeSlots(address))?;
            let id = self.free_id().ok_or_else(|| breakpoint::Error::NoFreeIds(address))?;

            let kind = breakpoint_type(trigger)?;
            let len_field = breakpoint_len_field(size)?;

            self.regs.hardware[slot] = address as _;
            self.regs.kind[slot] = kind;
            self.regs.len[slot] = len_field;
            self.regs.mapping[slot] = id;

            Ok(id)
        }

        pub fn unset_watchpoint(&mut self, id: i32) {
            if let Some(slot) = self.regs.mapping.iter().position(|&m| m == id) {
                self.regs.mapping[slot] = -1;
            }
        }

        pub fn read_register(pid: Pid, id: usize) -> nix::Result<Word> {
            ptrace(Request::PTRACE_PEEKUSER, pid, debug_offset(id), 0).map(|v| v as Word)
        }

        pub fn write_register(pid: Pid, id: usize, value: Word) -> nix::Result<()> {
            ptrace(Request::PTRACE_POKEUSER, pid, debug_offset(id), value).map(|_| ())
        }
    }

    #[derive(Clone)]
    #[repr(transparent)]
    pub struct RegisterSet(libc::user_regs_struct);

    impl Default for RegisterSet {
        fn default() -> Self {
            Self(unsafe { std::mem::MaybeUninit::zeroed().assume_init() })
        }
    }

    impl PartialEq for RegisterSet {
        fn eq(&self, other: &RegisterSet) -> bool {
            let size = std::mem::size_of::<Self>();
            unsafe {
                libc::memcmp(
                    self as *const RegisterSet as *const _,
                    other as *const RegisterSet as *const _,
                    size,
                ) == 0
            }
        }
    }
    impl Eq for RegisterSet {}

    impl Deref for RegisterSet {
        type Target = libc::user_regs_struct;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl DerefMut for RegisterSet {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
        }
    }

    #[derive(Clone, Default)]
    pub struct Registers {
        regs: RegisterSet,
        orig: RegisterSet,
    }

    impl Registers {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn update(&mut self, pid: Pid) -> nix::Result<()> {
            ptrace(
                Request::PTRACE_GETREGS,
                pid,
                0,
                &mut self.regs as *mut RegisterSet as *mut _,
            )
            .map(|_| ())?;

            self.orig = self.regs.clone();
            Ok(())
        }

        pub fn write(&mut self, pid: Pid) -> nix::Result<()> {
            ptrace(
                Request::PTRACE_SETREGS,
                pid,
                0,
                &mut self.regs as *mut RegisterSet as *mut _,
            )
            .map(|_| ())?;
            self.orig = self.regs.clone();
            Ok(())
        }

        pub fn write_modified(&mut self, pid: Pid) -> nix::Result<()> {
            if self.orig != self.regs {
                self.write(pid)?;
            }
            Ok(())
        }

        pub fn current(&self) -> &RegisterSet {
            &self.regs
        }

        pub fn current_mut(&mut self) -> &mut RegisterSet {
            &mut self.regs
        }
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub use self::x86::*;
