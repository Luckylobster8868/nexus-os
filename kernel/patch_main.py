import re
import sys

def patch_main():
    path = "src/main.rs"
    with open(path, "r") as f:
        content = f.read()

    # 1. Fix SYSCALL_KSTACK alignment
    old_kstack = "#[repr(align(16))]\nstatic mut SYSCALL_KSTACK: [u8; 8192] = [0u8; 8192];"
    new_kstack = "#[repr(align(16))]\nstruct SyscallStack([u8; 8192]);\nstatic mut SYSCALL_KSTACK: SyscallStack = SyscallStack([0u8; 8192]);"
    
    if old_kstack in content:
        content = content.replace(old_kstack, new_kstack)
    
    # 2. Add SFMask
    old_lstar = """    // LSTAR: syscall handler address
    let handler = syscall_handler as u64;
    core::arch::asm!("wrmsr", in("ecx") 0xC0000082u32,
        in("eax") handler as u32, in("edx") (handler >> 32) as u32,
        options(nomem, nostack));
}"""
    
    new_lstar = """    // LSTAR: syscall handler address
    let handler = syscall_handler as u64;
    core::arch::asm!("wrmsr", in("ecx") 0xC0000082u32,
        in("eax") handler as u32, in("edx") (handler >> 32) as u32,
        options(nomem, nostack));

    // FMASK: mask Interrupt Flag (IF) during syscall
    core::arch::asm!("wrmsr", in("ecx") 0xC0000084u32,
        in("eax") 0x200u32, in("edx") 0u32,
        options(nomem, nostack));
}"""
    
    if old_lstar in content:
        content = content.replace(old_lstar, new_lstar)
        
    with open(path, "w") as f:
        f.write(content)

if __name__ == "__main__":
    patch_main()
