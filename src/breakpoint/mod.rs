pub mod hardware;
pub mod software;

pub type Id = usize;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Breakpoint {
    Hardware(hardware::Breakpoint),
    Software(software::Breakpoint),
}

impl Breakpoint {
    pub fn is_hardware(&self) -> bool {
        matches!(self, Self::Hardware(_))
    }

    pub fn is_software(&self) -> bool {
        matches!(self, Self::Software(_))
    }
}
