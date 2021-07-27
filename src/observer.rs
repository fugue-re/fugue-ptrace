use crate::breakpoint::Breakpoint;
use crate::trace::{Error, Process};

#[allow(unused_variables)]
pub trait Observer: 'static {
    fn init(&mut self) -> Result<(), Error> { Ok(()) }
    fn fini(&mut self) -> Result<(), Error> { Ok(()) }

    fn start(&mut self, tracee: &mut Process, parent: &Option<&mut Process>) -> Result<(), Error> { Ok(()) }
    fn stop(&mut self, tracee: &mut Process) -> Result<(), Error> { Ok(()) }
    fn exec(&mut self, tracee: &mut Process) -> Result<(), Error> { Ok(()) }
    fn step(&mut self, tracee: &mut Process) -> Result<(), Error> { Ok(()) }
    fn breakpoint(&mut self, tracee: &mut Process, breakpoint: &Breakpoint) -> Result<(), Error> { Ok(()) }
    fn detach(&mut self, tracee: &mut Process) -> Result<(), Error> { Ok(()) }
    fn signal(&mut self, tracee: &mut Process) -> Result<(), Error> { Ok(()) }
    fn pre_call(&mut self, tracee: &mut Process) -> Result<(), Error> { Ok(()) }
    fn post_call(&mut self, tracee: &mut Process) -> Result<(), Error> { Ok(()) }
}
