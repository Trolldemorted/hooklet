// Credits to https://stackoverflow.com/a/775124/1569755 and https://stackoverflow.com/a/36511513/1569755
pub fn build_x86_64_far_jump(destination_address: usize) -> [u8; 0x13] {
    let mut code: [u8; 0x13] = [
        0x50, // push     rax
        0x50, // push     rax
        0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs   rax, 0x0000000000000000
        0x48, 0x89, 0x44, 0x24, 0x08, // mov      QWORD PTR [rsp+0x8], rax
        0x58, // pop      rax
        0xc3, // ret
    ];
    code[4..12].copy_from_slice(&destination_address.to_le_bytes());
    code
}
