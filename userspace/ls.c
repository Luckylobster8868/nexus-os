typedef unsigned long u64;
typedef long i64;
typedef unsigned short u16;
typedef unsigned char u8;

struct LinuxDirent64 {
    u64 d_ino;
    i64 d_off;
    u16 d_reclen;
    u8  d_type;
    char d_name[];
} __attribute__((packed));

void _start() {
    const char *path = "/";
    long fd = -1;
    // sys_open
    __asm__ volatile(
        "syscall"
        : "=a"(fd)
        : "a"(5), "D"(path), "S"(1) // O_RDONLY
        : "rcx", "r11", "memory"
    );

    if (fd < 0) {
        const char msg[] = "ls: open failed\n";
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
        // sys_getdents = 78
        __asm__ volatile(
            "syscall"
            : "=a"(bytes_read)
            : "a"(78), "D"(fd), "S"(buf), "d"(sizeof(buf))
            : "rcx", "r11", "memory"
        );

        if (bytes_read <= 0) {
            break; // 0 = EOF, <0 = error
        }

        long bpos = 0;
        while (bpos < bytes_read) {
            struct LinuxDirent64 *d = (struct LinuxDirent64 *)(buf + bpos);
            
            // Print name
            const char *name = d->d_name;
            int name_len = 0;
            while (name[name_len] != '\0') name_len++;

            long tmp;
            // sys_write to stdout
            __asm__ volatile(
                "syscall"
                : "=a"(tmp)
                : "a"(1), "D"(1), "S"(name), "d"(name_len)
                : "rcx", "r11", "memory"
            );

            const char newline[] = "\n";
            __asm__ volatile(
                "syscall"
                : "=a"(tmp)
                : "a"(1), "D"(1), "S"(newline), "d"(1)
                : "rcx", "r11", "memory"
            );

            bpos += d->d_reclen;
        }
    }

exit:
    __asm__ volatile(
        "syscall\n"
        :
        : "a"(60), "D"(0)
        : "rcx", "r11", "memory"
    );
}
