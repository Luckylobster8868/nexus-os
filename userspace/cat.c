void _start() {
    // We want to open("/hello.txt", O_RDONLY) and read it in a loop
    // sys_open is rax=5, rdi=path, rsi=flags
    const char *path = "/hello.txt";
    long fd = -1;
    __asm__ volatile(
        "syscall"
        : "=a"(fd)
        : "a"(5), "D"(path), "S"(1) // 1 is O_RDONLY in vfs
        : "rcx", "r11", "memory"
    );

    if (fd < 0) {
        const char msg[] = "cat: open failed\n";
        long tmp;
        __asm__ volatile(
            "syscall"
            : "=a"(tmp)
            : "a"(1), "D"(1), "S"(msg), "d"(sizeof(msg) - 1)
            : "rcx", "r11", "memory"
        );
        goto exit;
    }

    char buf[1024];
    while (1) {
        long bytes_read = -1;
        __asm__ volatile(
            "syscall"
            : "=a"(bytes_read)
            : "a"(0), "D"(fd), "S"(buf), "d"(sizeof(buf))
            : "rcx", "r11", "memory"
        );

        if (bytes_read <= 0) {
            break;
        }

        long bytes_written = -1;
        __asm__ volatile(
            "syscall"
            : "=a"(bytes_written)
            : "a"(1), "D"(1), "S"(buf), "d"(bytes_read)
            : "rcx", "r11", "memory"
        );
    }

exit:
    __asm__ volatile(
        "movq $60, %%rax\n"
        "xorq %%rdi, %%rdi\n"
        "syscall\n"
        ::: "rax", "rdi", "rcx", "r11", "memory"
    );
}
