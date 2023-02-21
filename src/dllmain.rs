use std::ffi::{CStr, c_char};

fn sig_to_vec(sig: &str) -> Vec<Option<u8>> {
    let split: Vec<&str> = sig.split(" ").collect();
    split.into_iter().map(|x| {
        if x == "?" || x == "??" {
            None
        } else {
            Some(u8::from_str_radix(x, 16).unwrap())
        }
    }).collect()
}

#[no_mangle]
unsafe extern "C" fn find_sig(base_addr: *const u8, mod_size: usize, sig_ptr: *const c_char) -> *const u8 {
    let sig = CStr::from_ptr(sig_ptr).to_str().unwrap();
    let sig_vec = sig_to_vec(sig);
    let sig_bytes = sig_vec.as_slice();
    let sig_len = sig_bytes.len();

    let mut sig_index = 0;
    for i in 0 .. mod_size {
        let ptr = base_addr.add(i);

        let sig_byte = sig_bytes[sig_index];
        let is_matching = match sig_byte {
            Some(s) => s == *(ptr as *const u8),
            None => true
        };

        if is_matching {
            sig_index += 1;
            if sig_index != sig_len { continue; }

            let start = ptr.sub(sig_index - 1);
            if *start == 0xE8 { // Relative call
                let asm_ptr = *(start.add(1) as *const u32);
                return start.sub(!asm_ptr as usize).add(4);
            }
            return start;
        } else if sig_index > 0 {
            sig_index = 0;
        }
    }

    return 0 as _;
}