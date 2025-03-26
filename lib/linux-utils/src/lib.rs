use std::borrow::Cow;
use std::ffi::CString;
use std::ffi::CStr;

pub type LinuxTid = i32;

pub fn gettid() -> i32
{
	unsafe { libc::gettid() }
}

pub fn prctl_set_name(name: Cow<'static, str>)
{
	let trimmed = if name.len() > 15 {
		&name[..15]
	} else {
		&name
	};
	
	let cname = CString::new(trimmed).unwrap();
	unsafe {
		libc::prctl(libc::PR_SET_NAME, cname.as_ptr() as usize, 0, 0, 0);
	}
}

pub fn prctl_get_name() -> String {
	let mut buf = [0u8; 16]; // 15文字 + null 終端
    
	unsafe {
		libc::prctl(libc::PR_GET_NAME, buf.as_mut_ptr() as *mut libc::c_void, 0, 0, 0);
	}

	let cstr = unsafe { CStr::from_ptr(buf.as_ptr() as *const i8) };
	cstr.to_string_lossy().into_owned()
}

#[test]
fn test_prctl()
{
	let name = prctl_get_name();
	println!("comm: {}", name);

	prctl_set_name(Cow::from("hoge"));
	let name = prctl_get_name();
	println!("comm: {}", name);
}
