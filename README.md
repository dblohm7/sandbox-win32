sandbox-win32
=============

This is a testbed for researching the behaviour of code when running under a
sandboxed Win32 process. At its core, it implements the ideas behind David
LeBlanc's excellent series [[1](https://blogs.msdn.microsoft.com/david_leblanc/2007/07/27/practical-windows-sandboxing-part-1/)][[2](https://blogs.msdn.microsoft.com/david_leblanc/2007/07/30/practical-windows-sandboxing-part-2/)][[3](https://blogs.msdn.microsoft.com/david_leblanc/2007/07/31/practical-windows-sandboxing-part-3/)]
of blog posts on the topic. As both the blog posts and the original revision of
this code are rather dated at this point (2007 and 2013, respectively), I have
continued to update the sandbox with additional features as Windows' security
features continue to evolve.

The sandbox consists of two classes: `WindowsSandbox` and
`WindowsSandboxLauncher`.

Any implementation of a sandboxed process needs to derive from `WindowsSandbox`
and implement its virtual functions. `OnPrivInit` is executed while the
sandboxed process is running with an impersonation token, imbuing the process
with additional rights. Once `OnPrivInit` has finished executing, the sandbox
reverts to its restricted token, adds itself to a job object, and then runs
`OnInit`, which is where untrusted initialization code should be run. `OnFini`
may also be implemented for cleanup code.

`WindowsSandboxLauncher` is used to prepare and launch the sandboxed process.
`WindowsSandbox` does not provide sandboxing on its own, but only when used in
tandem with `WindowsSandboxLauncher`.

### Included Programs

`proto` was an experimental implementation of a sandbox for EME (now known as
GMP) plug-ins. Its job was to load an untrusted DLL as a data file, verify that
its entry point was set to NULL, and then run its (de)initialization routines.

`comtest` is the newest experiment to determine the behaviour of COM over RPC
when communicating between a parent process with normal privileges and a
sandboxed child process.

## Building this software

This repository uses [`tup`](http://gittup.org/tup/) as its build system.
Provided that the `tup` binaries are installed and available on your system
`PATH`, you should be able to run `tup` from the repository's root directory and
be able to build the binaries.

This code was written and successfully built using Visual C++ 2013 Community
Edition. It requires Windows SDK version 10.0.10586.0 in order to correctly
build with the latest Windows 10 security features.
