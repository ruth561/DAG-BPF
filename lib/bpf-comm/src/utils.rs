use std::ffi::CStr;

fn get_errno() -> i32 {
	unsafe { *libc::__errno_location() }
}

pub fn get_errno_string() -> String {
	unsafe {
		let c_str = libc::strerror(get_errno());
		if c_str.is_null() {
			"Unknown error".to_string()
		} else {
			CStr::from_ptr(c_str).to_string_lossy().into_owned()
		}
	}
}
