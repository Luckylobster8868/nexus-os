// tcpserver.c - Userspace TCP server for Noxisa
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

static inline long sys_close(int fd) {
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(3), "D"(fd)
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

static inline long sys_accept(int fd, struct sockaddr_in *addr, uint32_t *addrlen) {
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(43), "D"(fd), "S"(addr), "d"(addrlen)
        : "rcx", "r11", "r8", "r9", "r10", "memory"
    );
    return ret;
}

static inline long sys_bind(int fd, const struct sockaddr_in *addr, uint32_t addrlen) {
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(49), "D"(fd), "S"(addr), "d"(addrlen)
        : "rcx", "r11", "r8", "r9", "r10", "memory"
    );
    return ret;
}

static inline long sys_listen(int fd, int backlog) {
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(50), "D"(fd), "S"(backlog)
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

int my_strlen(const char* s) {
    int i = 0;
    while(s[i]) i++;
    return i;
}

void print(const char* s) {
    sys_write(1, s, my_strlen(s));
}

void _start() {
    print("tcpserver: Userspace TCP server starting...\n");
    
    int listen_fd = sys_socket(2, 1, 0); // AF_INET, SOCK_STREAM
    if (listen_fd < 0) {
        print("tcpserver: socket() failed\n");
        sys_exit(1);
    }
    print("tcpserver: socket created (fd=");
    char fd_ch = '0' + listen_fd;
    sys_write(1, &fd_ch, 1);
    print(")\n");

    struct sockaddr_in addr;
    addr.sin_family = 2; // AF_INET
    addr.sin_port = htons(8080);
    addr.sin_addr = 0; // INADDR_ANY (0.0.0.0)
    for (int i = 0; i < 8; i++) addr.sin_zero[i] = 0;

    if (sys_bind(listen_fd, &addr, sizeof(addr)) < 0) {
        print("tcpserver: bind() failed\n");
        sys_close(listen_fd);
        sys_exit(1);
    }
    print("tcpserver: bound to port 8080\n");

    if (sys_listen(listen_fd, 1) < 0) {
        print("tcpserver: listen() failed\n");
        sys_close(listen_fd);
        sys_exit(1);
    }
    print("tcpserver: listening on 0.0.0.0:8080, waiting for client...\n");

    struct sockaddr_in client_addr;
    uint32_t client_len = sizeof(client_addr);
    int client_fd = sys_accept(listen_fd, &client_addr, &client_len);
    if (client_fd < 0) {
        print("tcpserver: accept() failed\n");
        sys_close(listen_fd);
        sys_exit(1);
    }
    print("tcpserver: client connection accepted! (client_fd=");
    char cfd_ch = '0' + client_fd;
    sys_write(1, &cfd_ch, 1);
    print(")\n");

    // Read request from client (retry until received or client closes)
    char buf[512];
    long n = -1;
    for (int retry = 0; retry < 500000; retry++) {
        n = sys_read(client_fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            print("tcpserver: received request from client:\n");
            sys_write(1, buf, n);
            break;
        } else if (n == 0) {
            break;
        }
    }

    // Send HTTP response
    const char *resp = "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nHello from Noxisa TCP Server!\n";
    print("tcpserver: sending response...\n");
    while (sys_write(client_fd, resp, my_strlen(resp)) < 0) {}

    print("tcpserver: closing client connection...\n");
    sys_close(client_fd);

    print("tcpserver: closing listening socket...\n");
    sys_close(listen_fd);

    print("tcpserver: PASS\n");
    sys_exit(0);
}
