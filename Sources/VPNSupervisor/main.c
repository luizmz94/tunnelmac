// Per-connection supervisor started by the privileged helper (VPNHelper).
// No installation, shell, PATH lookup, or VPN protocol of its own.
//
// Usage: VPNSupervisor [--cookie-fd] <client> [client arguments...]   (openfortivpn)
//        VPNSupervisor --openvpn <client>                              (openvpn, no other argument)
//        VPNSupervisor --wireguard <client>                            (wireguard-go, no other argument)
//        VPNSupervisor --openconnect <client> <server>                 (openconnect, GlobalProtect)
//   fd 0      control channel: "STOP\n" or EOF requests a normal stop
//   fd 1, 2   output channel (the same socket as fd 0)
//   fd 3      protected configuration: an already-unlinked regular file, mode 0600
//   fd 4      with --cookie-fd: SAML session cookie, read once and validated;
//             with --openconnect: the password or GlobalProtect cookie, one line on stdin
// The helper builds the client arguments itself; secrets never travel in argv/env.
// openfortivpn reads fd 3 with "-c /dev/fd/3"; openvpn with "--config /dev/fd/3", where the
// helper has already inlined key material and credentials. wireguard-go runs in the
// foreground on a new utun ("-f utun") and never sees fd 3: the helper sends its keys over
// the root-only UAPI socket and configures addresses, routes and DNS itself. openconnect
// reads "--config=/dev/fd/3 --passwd-on-stdin <server>"; its vpnc-script is the helper's own.
#define __STDC_WANT_LIB_EXT1__ 1 // memset_s
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <grp.h>

// Matches COOKIE_SIZE in openfortivpn: --cookie-on-stdin performs a single read of
// at most 4096 bytes, prefix included.
#define COOKIE_LIMIT 4096
#define COOKIE_PREFIX "SVPNCOOKIE="
#define CONFIG_FD 3
#define COOKIE_FD 4
// One stdin line for openconnect --passwd-on-stdin.
#define SECRET_LIMIT 4096

static volatile sig_atomic_t interrupted;
static void request_stop(int number) { (void)number; interrupted = 1; }
static int fail(const char *message) {
    fprintf(stdout, "ERROR: Supervisor: %s (%s).\n", message, strerror(errno));
    fprintf(stdout, "__VPNGUI_EXIT__=125\n");
    fflush(stdout);
    return 125;
}

// The configuration must be a private, anonymous file: regular, owned by us,
// no group/other bits and no remaining directory entry (already unlinked).
static int check_config(void) {
    struct stat info;
    if (fstat(CONFIG_FD, &info)) return fail("configuração protegida ausente");
    if (!S_ISREG(info.st_mode) || (info.st_mode & 0077) || info.st_uid != geteuid() || info.st_nlink != 0) {
        errno = EACCES; return fail("configuração protegida inválida");
    }
    if (lseek(CONFIG_FD, 0, SEEK_SET) < 0) return fail("configuração protegida inválida");
    return 0;
}

// Reads the session cookie from fd 4 into a fresh pipe that becomes the client's stdin.
// The value never travels through argv, the environment, or the STOP control channel.
static int load_cookie(int *descriptor) {
    *descriptor = -1;
    struct stat info;
    if (fstat(COOKIE_FD, &info)) return fail("sessão SAML protegida ausente");
    if (!(S_ISFIFO(info.st_mode) || (S_ISREG(info.st_mode) && !(info.st_mode & 0077) && info.st_nlink == 0))) {
        close(COOKIE_FD); errno = EACCES; return fail("sessão SAML temporária inválida");
    }
    char value[COOKIE_LIMIT + 1];
    size_t length = 0;
    for (;;) {
        ssize_t count = read(COOKIE_FD, value + length, sizeof(value) - length);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) { close(COOKIE_FD); memset_s(value, sizeof(value), 0, sizeof(value)); return fail("não foi possível ler a sessão SAML"); }
        if (count == 0) break;
        length += (size_t)count;
        if (length == sizeof(value)) break;
    }
    close(COOKIE_FD);
    size_t prefix = strlen(COOKIE_PREFIX);
    int valid = length > prefix && length <= COOKIE_LIMIT && memcmp(value, COOKIE_PREFIX, prefix) == 0;
    for (size_t i = 0; valid && i < length; ++i)
        if ((unsigned char)value[i] <= 0x20 || (unsigned char)value[i] >= 0x7f || value[i] == ';') valid = 0;
    if (!valid) {
        memset_s(value, sizeof(value), 0, sizeof(value));
        errno = EINVAL; return fail("sessão SAML em formato inesperado");
    }
    int channel[2];
    if (pipe(channel)) { memset_s(value, sizeof(value), 0, sizeof(value)); return fail("não foi possível criar o canal da sessão SAML"); }
    // An empty pipe holds well over 4096 bytes, so this write cannot block on the reader.
    size_t written = 0;
    while (written < length) {
        ssize_t count = write(channel[1], value + written, length - written);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) break;
        written += (size_t)count;
    }
    memset_s(value, sizeof(value), 0, sizeof(value));
    close(channel[1]); // EOF right after the value: the client never waits for more input.
    if (written != length) { close(channel[0]); errno = EIO; return fail("não foi possível entregar a sessão SAML"); }
    // Move away from 0-4 so later dup2 calls cannot overwrite it; never inherited by exec.
    int high = fcntl(channel[0], F_DUPFD_CLOEXEC, 10);
    close(channel[0]);
    if (high < 0) return fail("não foi possível preparar o canal da sessão SAML");
    *descriptor = high;
    return 0;
}

// Reads the openconnect password or cookie from fd 4 into a fresh pipe that becomes the
// client's stdin, followed by one newline. No control characters: the value is one line.
static int load_secret(int *descriptor) {
    *descriptor = -1;
    struct stat info;
    if (fstat(COOKIE_FD, &info)) return fail("credencial protegida ausente");
    if (!S_ISFIFO(info.st_mode)) { close(COOKIE_FD); errno = EACCES; return fail("credencial temporária inválida"); }
    char value[SECRET_LIMIT + 2];
    size_t length = 0;
    for (;;) {
        ssize_t count = read(COOKIE_FD, value + length, SECRET_LIMIT + 1 - length);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) { close(COOKIE_FD); memset_s(value, sizeof(value), 0, sizeof(value)); return fail("não foi possível ler a credencial"); }
        if (count == 0) break;
        length += (size_t)count;
        if (length == SECRET_LIMIT + 1) break;
    }
    close(COOKIE_FD);
    int valid = length > 0 && length <= SECRET_LIMIT;
    for (size_t i = 0; valid && i < length; ++i)
        if ((unsigned char)value[i] < 0x20 || (unsigned char)value[i] == 0x7f) valid = 0;
    if (!valid) {
        memset_s(value, sizeof(value), 0, sizeof(value));
        errno = EINVAL; return fail("credencial em formato inesperado");
    }
    value[length++] = '\n';
    int channel[2];
    if (pipe(channel)) { memset_s(value, sizeof(value), 0, sizeof(value)); return fail("não foi possível criar o canal da credencial"); }
    size_t written = 0;
    while (written < length) {
        ssize_t count = write(channel[1], value + written, length - written);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) break;
        written += (size_t)count;
    }
    memset_s(value, sizeof(value), 0, sizeof(value));
    close(channel[1]);
    if (written != length) { close(channel[0]); errno = EIO; return fail("não foi possível entregar a credencial"); }
    int high = fcntl(channel[0], F_DUPFD_CLOEXEC, 10);
    close(channel[0]);
    if (high < 0) return fail("não foi possível preparar o canal da credencial");
    *descriptor = high;
    return 0;
}

int main(int argc, char **argv) {
    int use_cookie = 0, openvpn = 0, wireguard = 0, openconnect = 0;
    if (argc >= 2 && strcmp(argv[1], "--cookie-fd") == 0) {
        use_cookie = 1;
        argv += 1; argc -= 1;
    } else if (argc >= 2 && strcmp(argv[1], "--openvpn") == 0) {
        openvpn = 1;
        argv += 1; argc -= 1;
        // Everything else is in the protected configuration.
        if (argc != 2) { errno = EINVAL; return fail("argumentos inválidos para openvpn"); }
    } else if (argc >= 2 && strcmp(argv[1], "--wireguard") == 0) {
        wireguard = 1;
        argv += 1; argc -= 1;
        // The interface is always a new utun; the configuration arrives over UAPI.
        if (argc != 2) { errno = EINVAL; return fail("argumentos inválidos para wireguard-go"); }
    } else if (argc >= 2 && strcmp(argv[1], "--openconnect") == 0) {
        openconnect = 1;
        argv += 1; argc -= 1;
        // Only the server; every option is in the protected configuration.
        if (argc != 3 || argv[2][0] == '-' || argv[2][0] == '\0') { errno = EINVAL; return fail("argumentos inválidos para openconnect"); }
    }
    if (argc < 2 || argv[1][0] != '/') { errno = EINVAL; return fail("argumentos inválidos"); }
    for (int i = 2; i < argc; ++i) {
        // The cookie may only arrive through the dedicated stdin pipe.
        if (strncmp(argv[i], "--cookie", 8) == 0) { errno = EINVAL; return fail("argumento de sessão não permitido"); }
    }
    sigset_t empty;
    sigemptyset(&empty);
    sigprocmask(SIG_SETMASK, &empty, NULL);
    signal(SIGCHLD, SIG_DFL); // Keep children waitable; do not reap them in a handler.
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, request_stop);
    signal(SIGTERM, request_stop);
    signal(SIGHUP, request_stop);

    if (check_config()) { if (use_cookie || openconnect) close(COOKIE_FD); return 125; }
    int cookie = -1;
    if (use_cookie && load_cookie(&cookie)) return 125;
    if (openconnect && load_secret(&cookie)) return 125;
    if (!use_cookie && !openconnect) close(COOKIE_FD); // Never inherit an unexpected descriptor 4.

    // Every input stays in argv or in the descriptor, never in command text.
    char **arguments = calloc((size_t)argc + 4, sizeof(char *));
    if (!arguments) { if (cookie >= 0) close(cookie); return fail("memória insuficiente"); }
    int position = 0;
    arguments[position++] = argv[1];
    if (openconnect) {
        arguments[position++] = "--config=/dev/fd/3";
        arguments[position++] = "--passwd-on-stdin";
        arguments[position++] = argv[2];
    } else {
        for (int i = 2; i < argc; ++i) arguments[position++] = argv[i];
    }
    if (cookie >= 0 && !openconnect) arguments[position++] = "--cookie-on-stdin";
    if (wireguard) {
        arguments[position++] = "-f";
        arguments[position++] = "utun";
    } else if (!openconnect) {
        arguments[position++] = openvpn ? "--config" : "-c";
        arguments[position++] = "/dev/fd/3";
    }
    arguments[position] = NULL;

    pid_t child = fork();
    if (child < 0) { if (cookie >= 0) close(cookie); free(arguments); return fail("não foi possível criar o processo"); }
    if (child == 0) {
        if (setpgid(0, 0) != 0) _exit(125);
        // A STOP can arrive before exec. Do not inherit the supervisor's handler:
        // it would consume SIGTERM and then start a client that never received it.
        signal(SIGTERM, SIG_DFL);
        signal(SIGINT, SIG_DFL);
        signal(SIGHUP, SIG_DFL);
        signal(SIGPIPE, SIG_DFL);
        if (interrupted) _exit(143);
        if (wireguard) close(CONFIG_FD); // Nothing for wireguard-go to read there.
        else if (fcntl(CONFIG_FD, F_SETFD, 0) < 0) _exit(125);
        if (dup2(STDOUT_FILENO, STDERR_FILENO) < 0) _exit(125);
        // pppd checks the real UID, unlike openfortivpn's EUID check. A launchd daemon
        // already runs with every ID at 0; normalize anyway and verify before exec.
        // Unprivileged local fixtures skip this block.
        if (geteuid() == 0) {
            gid_t root_group = 0;
            if (setgroups(1, &root_group) || setgid(0) || setuid(0)) {
                fprintf(stderr, "ERROR: Supervisor: não foi possível preparar a identidade root (%s).\n", strerror(errno));
                _exit(125);
            }
            if (getuid() != 0 || geteuid() != 0 || getgid() != 0 || getegid() != 0) {
                fprintf(stderr, "ERROR: Supervisor: identidade root incompleta; cliente não iniciado.\n");
                _exit(125);
            }
        }
        // stdin is the dedicated cookie/credential pipe when there is one, otherwise /dev/null.
        // The supervisor's own stdin stays the STOP control channel and is never inherited.
        int input = cookie >= 0 ? cookie : open("/dev/null", O_RDONLY);
        if (input < 0 || dup2(input, STDIN_FILENO) < 0) _exit(125);
        // The original client inherits only stdio plus the protected config descriptor.
        int maximum = getdtablesize();
        for (int fd = 4; fd < maximum; ++fd) close(fd);
        execv(arguments[0], arguments);
        fprintf(stderr, "ERROR: Supervisor: não foi possível executar o cliente (%s).\n", strerror(errno));
        _exit(125);
    }
    (void)setpgid(child, child); // Private client group; never signal the helper/supervisor group.
    close(CONFIG_FD);
    if (cookie >= 0) close(cookie);
    free(arguments);
    printf("__VPNGUI_PID__=%ld\n", (long)child);
    fflush(stdout);

    int status = 0, stopping = 0, channel_open = 1;
    struct timespec stop_time = {0};
    char command[32];
    size_t length = 0;
    int oversized = 0;
    for (;;) {
        pid_t exited = waitpid(child, &status, WNOHANG);
        if (exited == child) break;
        if (exited < 0 && errno != EINTR) return fail("não foi possível aguardar a limpeza");
        // Until waitpid returns this child, its PID cannot be reused by another process.
        if (interrupted && !stopping) {
            kill(child, SIGTERM); stopping = 1;
            clock_gettime(CLOCK_MONOTONIC, &stop_time);
        }
        if (stopping == 1) {
            struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
            if (now.tv_sec - stop_time.tv_sec >= 10) {
                fprintf(stderr, "ERROR: Cliente não encerrou em 10 s; encerramento forçado, confira a recuperação da rede.\n");
                kill(-child, SIGKILL); stopping = 2;
            }
        }
        struct pollfd descriptor = { .fd = channel_open ? STDIN_FILENO : -1, .events = POLLIN | POLLHUP };
        int available = poll(&descriptor, 1, 200);
        if (available < 0) {
            if (errno == EINTR) continue;
            interrupted = 1; channel_open = 0; continue;
        }
        if (available == 0) continue; // An idle control channel is never an exit request.
        char buffer[128];
        ssize_t count = read(STDIN_FILENO, buffer, sizeof(buffer));
        if (count < 0 && errno == EINTR) continue;
        // EOF: the helper (or its connection to the app) is gone. Stop normally.
        if (count <= 0) { interrupted = 1; channel_open = 0; continue; }
        for (ssize_t i = 0; i < count; ++i) {
            if (buffer[i] == '\n') {
                command[length] = '\0';
                if (!oversized && strcmp(command, "STOP") == 0) interrupted = 1;
                length = 0; oversized = 0;
            } else if (length + 1 < sizeof(command)) {
                command[length++] = buffer[i];
            } else { oversized = 1; }
        }
    }
    int code = WIFEXITED(status) ? WEXITSTATUS(status) : WIFSIGNALED(status) ? 128 + WTERMSIG(status) : 125;
    printf("__VPNGUI_EXIT__=%d\n", code);
    fflush(stdout);
    return code;
}
