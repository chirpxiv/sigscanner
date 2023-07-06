use std::ffi::{c_char, CString};

pub unsafe fn read<T>(ptr: *const u8, offset: isize) -> T where T : Copy {
	*(ptr.offset(offset) as *const T)
}

pub unsafe fn read_str(ptr: *const u8, offset: isize) -> String {
	CString::from_raw(ptr.offset(offset) as *mut c_char)
		.into_string()
		.unwrap_or(String::default())
}