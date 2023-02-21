use std::ffi::{CStr, c_char};

fn parse_sig_str(sig: &str) -> Vec<Option<u8>> {
	let split: Vec<&str> = sig.split(" ").collect();
	split.into_iter().map(|x| {
		if x == "??" {
			None
		} else {
			Some(u8::from_str_radix(x, 16).unwrap())
		}
	}).collect()
}

#[no_mangle]
unsafe extern "C" fn find_sig(base_addr: *const u8, mod_size: usize, sig_ptr: *const c_char) -> *const u8 {
	let sig_str = CStr::from_ptr(sig_ptr).to_str().unwrap();
	let parsed = parse_sig_str(sig_str);

	// not ideal but this is an optimisation overall because accesing vectors is slow
	let sig_bytes = parsed.as_slice();
	let sig_len = sig_bytes.len();

	let mut sig_index = 0;
	for i in 0 .. mod_size {
		let ptr = base_addr.add(i);

		let sig_byte = sig_bytes[sig_index];
		let matches = match sig_byte {
			Some(s) => s == *ptr,
			None => true
		};

		if matches {
			sig_index += 1;
			if sig_index != sig_len { continue; }

			let start = ptr.sub(sig_index - 1);
			return if *start == 0xE8 { // relative call
				let asm_ptr = *(start.add(1) as *const u32);
				start.sub(!asm_ptr as usize).add(4)
			} else {
				start
			}
		} else if sig_index > 0 {
			sig_index = 0;
		}
	}

	return std::ptr::null();
}