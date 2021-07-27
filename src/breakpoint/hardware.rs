#![allow(non_upper_case_globals)]

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod x86 {
    use bitflags::bitflags;
    use libc::{PROT_EXEC, PROT_READ, PROT_WRITE};
    use nix::unistd::Pid;
    use thiserror::Error;

    use crate::arch;
    use crate::arch::Word;

    #[derive(Debug, Error)]
    pub enum Error {
        #[error("unable to set breakpoint using specified size {0}")]
        InvalidSize(usize),
        #[error("unable to set breakpoint using specified trigger {0:?}")]
        InvalidTrigger(Trigger),
        #[error("unable to set breakpoint at {0:#x}; no free IDs")]
        NoFreeIds(Word),
        #[error("unable to set breakpoint at {0:#x}; no free slots")]
        NoFreeSlots(Word),
        #[error("unable to resolve breakpoint to an address for {0}")]
        Resolve(Pid),
    }

    bitflags! {
        pub struct Flags: u32 {
            const CopyChild = 0x01;
            const CopyExec  = 0x02;
            const Disabled  = 0x04;
        }
    }

    bitflags! {
        pub struct Trigger: i32 {
            const Read = PROT_READ;
            const Write = PROT_WRITE;
            const Execute = PROT_EXEC;
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    pub struct Breakpoint {
        address: Word,
        flags: Flags,
        dr_index: Option<i32>,
        size: usize,
        trigger: Trigger,
    }

    impl Breakpoint {
        pub fn new(address: Word, size: usize, trigger: Trigger, flags: Flags) -> Result<Self, Error> {
            arch::breakpoint_type(trigger)?;
            arch::breakpoint_len_field(size)?;

            Ok(Self {
                address,
                size,
                trigger,
                flags,
                dr_index: None,
            })
        }

        pub fn disable(&mut self) {
            self.flags.insert(Flags::Disabled)
        }

        pub fn disabled(&self) -> bool {
            self.flags.intersects(Flags::Disabled)
        }

        pub fn enable(&mut self) {
            self.flags.remove(Flags::Disabled)
        }

        pub fn enabled(&self) -> bool {
            !self.flags.intersects(Flags::Disabled)
        }

        pub fn index(&self) -> Option<i32> {
            self.dr_index
        }

        pub fn update_index(&mut self, index: i32) {
            self.dr_index = if index < 0 { None } else { Some(index) };
        }

        pub fn clear_index(&mut self) {
            self.dr_index = None;
        }

        pub fn copy_on_exec(&self) -> bool {
            self.flags.intersects(Flags::CopyExec)
        }

        pub fn copy_on_fork(&self) -> bool {
            self.flags.intersects(Flags::CopyChild)
        }

        pub fn address(&self) -> Word {
            self.address
        }

        pub fn trigger(&self) -> Trigger {
            self.trigger
        }

        pub fn size(&self) -> usize {
            self.size
        }
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub use self::x86::*;
