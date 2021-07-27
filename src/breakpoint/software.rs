#![allow(non_upper_case_globals)]

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod x86 {
    use bitflags::bitflags;

    use crate::arch::Word;

    bitflags! {
        pub struct Flags: u32 {
            const CopyChild = 0x01;
            const CopyExec  = 0x02;
            const Disabled  = 0x04;
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    pub enum Kind {
        OneShot,
        Counter(usize),
        Persistent,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    pub struct Breakpoint {
        address: Word,
        replacement: Option<Word>,
        kind: Kind,
        flags: Flags,
        masked: bool,
    }

    impl Breakpoint {
        pub fn new(address: Word, kind: Kind, flags: Flags) -> Self {
            Self {
                address,
                replacement: None,
                kind,
                flags,
                masked: false,
            }
        }

        pub fn disable(&mut self) {
            self.flags.insert(Flags::Disabled)
        }

        pub fn enable(&mut self) {
            self.flags.remove(Flags::Disabled)
        }

        pub fn disabled(&self) -> bool {
            self.flags.intersects(Flags::Disabled)
        }

        pub fn copy_on_exec(&self) -> bool {
            self.flags.intersects(Flags::CopyExec)
        }

        pub fn copy_on_fork(&self) -> bool {
            self.flags.intersects(Flags::CopyChild)
        }

        pub fn one_shot(&self) -> bool {
            matches!(self.kind, Kind::Counter(1) | Kind::OneShot)
        }

        pub fn counter(&self) -> bool {
            matches!(self.kind, Kind::Counter(_))
        }

        pub fn persistent(&self) -> bool {
            matches!(self.kind, Kind::Persistent)
        }

        pub fn address(&self) -> Word {
            self.address
        }

        pub fn original(&self) -> Option<Word> {
            self.replacement
        }

        pub fn original_mut(&mut self) -> &mut Option<Word> {
            &mut self.replacement
        }

        pub fn replacement(&self) -> Option<Word> {
            self.original().map(Self::replacement_for)
        }

        pub fn replacement_for(word: Word) -> Word {
            (word & !0xff) | 0xcc
        }

        pub fn is_set(&self, current_val: Word) -> bool {
            matches!(self.replacement(), Some(v) if v == current_val)
        }

        pub fn unmask(&mut self) {
            self.masked = false;
        }

        pub fn masked(&self) -> bool {
            self.masked
        }

        pub fn update_hit(&mut self) -> bool {
            let enabled = match self.kind {
                Kind::OneShot => false,
                Kind::Counter(ref mut n) => {
                    *n = n.checked_sub(1).unwrap_or(0);
                    *n != 0
                },
                Kind::Persistent => true,
            };

            if !enabled {
                self.disable();
            } else {
                self.masked = true;
            }

            enabled
        }
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub use self::x86::*;
