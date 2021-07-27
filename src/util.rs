use nix::libc;
use nix::errno::Errno;
use nix::sys::ptrace::{AddressType, Request, RequestType};
use nix::sys::wait::{WaitPidFlag, WaitStatus};
use nix::unistd::Pid;

use std::os::raw::{c_long, c_void};

pub trait AsPid {
    fn as_pid(self) -> Pid;
}

impl AsPid for Pid {
    fn as_pid(self) -> Pid {
        self
    }
}

impl AsPid for &Pid {
    fn as_pid(self) -> Pid {
        *self
    }
}

impl AsPid for i32 {
    fn as_pid(self) -> Pid {
        Pid::from_raw(self)
    }
}

#[repr(transparent)]
pub struct AddressLike(AddressType);

impl From<AddressType> for AddressLike {
    fn from(t: AddressType) -> Self {
        Self(t)
    }
}

impl From<i32> for AddressLike {
    fn from(t: i32) -> Self {
        Self(t as _)
    }
}

impl From<u32> for AddressLike {
    fn from(t: u32) -> Self {
        Self(t as _)
    }
}

impl From<u64> for AddressLike {
    fn from(t: u64) -> Self {
        Self(t as _)
    }
}

impl From<usize> for AddressLike {
    fn from(t: usize) -> Self {
        Self(t as _)
    }
}

#[repr(transparent)]
pub struct DataLike(*mut c_void);

impl From<*mut c_void> for DataLike {
    fn from(t: *mut c_void) -> Self {
        Self(t)
    }
}

impl From<i32> for DataLike {
    fn from(t: i32) -> Self {
        Self(t as _)
    }
}

impl From<u32> for DataLike {
    fn from(t: u32) -> Self {
        Self(t as _)
    }
}

impl From<u64> for DataLike {
    fn from(t: u64) -> Self {
        Self(t as _)
    }
}

impl From<usize> for DataLike {
    fn from(t: usize) -> Self {
        Self(t as _)
    }
}

impl From<Option<i32>> for DataLike {
    fn from(t: Option<i32>) -> Self {
        match t {
            None => Self(std::ptr::null_mut()),
            Some(s) => Self::from(s as i32),
        }
    }
}

pub(crate) fn ptrace<A, D>(request: Request, pid: Pid, addr: A, data: D) -> nix::Result<c_long>
where A: Into<AddressLike>,
      D: Into<DataLike> {

    let addr = addr.into();
    let data = data.into();

    unsafe {
        Errno::result(libc::ptrace(request as RequestType, libc::pid_t::from(pid), addr.0, data.0))
    }
}

pub(crate) fn waitpid(pid: Pid, options: Option<WaitPidFlag>) -> nix::Result<(WaitStatus, i32)> {
    let mut status = 0;
    let option_bits = match options {
        Some(bits) => bits.bits(),
        None => 0,
    };

    let res = unsafe {
        libc::waitpid(
            pid.as_raw(),
            &mut status as *mut _,
            option_bits,
        )
    };

    match Errno::result(res)? {
        0 => Ok((WaitStatus::StillAlive, status)),
        res => WaitStatus::from_raw(Pid::from_raw(res), status).map(|r| (r, status)),
    }
}
