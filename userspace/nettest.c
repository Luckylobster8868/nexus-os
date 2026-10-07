// nettest.c - Userspace TCP client for Noxisa
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

struct sockaddr_in {
    uint16_t sin_family;
    uint16_t sin_port;
    uint32_t sin_addr;
    uint8_t  sin_zero[8];
};

static inline long sys_read(int fd, void *buf, uint64_t len) {
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(0), "D"(fd), "S"(buf), "d"(len)
        : "rcx", "r11", "r8", "r9", "r10", "memory"
    );
    return ret;
}

static inline long sys_write(int fd, const void *buf, uint64_t len) {
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(1), "D"(fd), "S"(buf), "d"(len)
        : "rcx", "r11", "r8", "r9", "r10", "memory"
    );
    return ret;
}

static inline long sys_socket(int domain, int type, int protocol) {
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(41), "D"(domain), "S"(type), "d"(protocol)
        : "rcx", "r11", "r8", "r9", "r10", "memory"
    );
    return ret;
}

static inline long sys_connect(int fd, const struct sockaddr_in *addr, uint32_t addrlen) {
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(42), "D"(fd), "S"(addr), "d"(addrlen)
        : "rcx", "r11", "r8", "r9", "r10", "memory"
    );
    return ret;
}

static inline void sys_exit(int status) {
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(60), "D"(status)
        : "rcx", "r11", "r8", "r9", "r10", "memory"
    );
    while (1) {}
}

uint16_t htons(uint16_t hostshort) { return (hostshort >> 8) | (hostshort << 8); }
uint32_t htonl(uint32_t hostlong) {
    return ((hostlong & 0x000000FF) << 24) | ((hostlong & 0x0000FF00) << 8) |
           ((hostlong & 0x00FF0000) >> 8) | ((hostlong & 0xFF000000) >> 24);
}
int my_strlen(const char* s) {
    int i = 0;
    while(s[i]) i++;
    return i;
}
void print(const char* s) {
    sys_write(1, s, my_strlen(s));
}

void _start() {
    print("nettest: Userspace TCP client starting...\n");
    int fd = sys_socket(2, 1, 0);
    if (fd < 0) {
        print("nettest: socket() failed\n");
        sys_exit(1);
    }
    struct sockaddr_in addr;
    addr.sin_family = 2; // AF_INET
    addr.sin_port = htons(8000);
    addr.sin_addr = htonl(0x0A000202);
    
    print("nettest: Connecting to 10.0.2.2:8000...\n");
    if (sys_connect(fd, &addr, sizeof(addr)) < 0) {
        print("nettest: connect() failed\n");
        sys_exit(1);
    }
    const char* request = "GET / HTTP/1.0\r\nHost: 10.0.2.2\r\nConnection: close\r\n\r\n";
    print("nettest: Sending HTTP request...\n");
    while (sys_write(fd, request, my_strlen(request)) < 0) {}
    print("nettest: Reading response...\n");
    char buf[128];
    while (1) {
        long n = sys_read(fd, buf, sizeof(buf));
        if (n < 0) { continue; }
        if (n == 0) { print("\nnettest: EOF\n"); break; }
        sys_write(1, buf, n);
    }
    print("\nnettest: PASS\n");
    sys_exit(0);
}
