use std::env;
use std::ffi::CString;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;

use nix::sys::personality;
use nix::sys::ptrace::Request as PTraceRequest;
use nix::unistd::{Pid, execvpe, fork, ForkResult};

use crate::util::ptrace;

#[derive(Debug, Clone)]
pub struct Command {
    path: OsString,
    args: Vec<OsString>,
    envs: Vec<OsString>,
    aslr: bool,
}

impl Command {
    pub fn new<P: AsRef<OsStr>>(command: P) -> Self {
        let path = command.as_ref().to_owned();
        Self {
            args: vec![path.clone()],
            envs: Default::default(),
            path,
            aslr: false,
        }
    }

    pub fn command(&self) -> &OsStr {
        &self.path
    }

    pub fn disable_aslr(&mut self) -> &mut Self {
        self.aslr = false;
        self
    }

    pub fn enable_aslr(&mut self) -> &mut Self {
        self.aslr = true;
        self
    }

    pub fn arg<A: AsRef<OsStr>>(&mut self, arg: A) -> &mut Self {
        self.args.push(arg.as_ref().to_owned());
        self
    }

    pub fn args<A: AsRef<OsStr>, I: IntoIterator<Item=A>>(&mut self, args: I) -> &mut Self {
        self.args.extend(args.into_iter().map(|arg| arg.as_ref().to_owned()));
        self
    }

    pub fn env<K: AsRef<OsStr>, V: AsRef<OsStr>>(&mut self, key: K, val: V) -> &mut Self {
        let k = key.as_ref().to_str().unwrap();
        let v = val.as_ref().to_str().unwrap();
        let kv = format!("{}={}", k, v);
        self.envs.push(OsString::from(kv));
        self
    }

    pub fn envs<K: AsRef<OsStr>, V: AsRef<OsStr>, I: IntoIterator<Item=(K, V)>>(&mut self, envs: I) -> &mut Self {
        for (k, v) in envs.into_iter() {
            self.env(k, v);
        }
        self
    }

    pub fn inherit_env(&mut self) -> &mut Self {
        for (k, v) in env::vars_os() {
            self.env(k, v);
        }
        self
    }

    pub fn launch(&self) -> nix::Result<Pid> {
        if let ForkResult::Parent { child } = unsafe { fork() }? {
            return Ok(child)
        }

        if !self.aslr {
            let mut pers = personality::get().expect("fetch personality");
            pers.insert(personality::Persona::ADDR_NO_RANDOMIZE);
            personality::set(pers).expect("update personality");
        }

        ptrace(PTraceRequest::PTRACE_TRACEME, Pid::from_raw(0), 0, 0)
            .expect("ptrace TRACEME");

        let path = CString::new(self.path.as_bytes())
            .unwrap();
        let args = self.args.iter()
            .map(|arg| CString::new(arg.as_bytes()).unwrap())
            .collect::<Vec<_>>();
        let envs = self.envs.iter()
            .map(|env| CString::new(env.as_bytes()).unwrap())
            .collect::<Vec<_>>();

        execvpe(path.as_ref(), args.as_ref(), envs.as_ref()).ok();

        unsafe { libc::exit(libc::EXIT_FAILURE) }
    }
}
