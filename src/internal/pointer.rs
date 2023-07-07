use std::ffi::{CStr, c_char};

pub unsafe fn read<T>(ptr: *const u8, offset: isize) -> T where T : Copy {
	*(ptr.offset(offset) as *const T)
}

pub unsafe fn read_str(ptr: *const u8, offset: isize) -> String {
	CStr::from_ptr(ptr.offset(offset) as *mut c_char).to_str()
		.unwrap_or(&String::default())
		.to_owned()
}