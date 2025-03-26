pub type LinuxTid = i32;

pub fn gettid() -> i32
{
	unsafe { libc::gettid() }
}
