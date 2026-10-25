#include "ProcessBridge.h"
#include <spawn.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <libproc.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <errno.h>
#include <grp.h>
#include <string.h>
#include <time.h>

static int high_copy(int fd) {
    // Move a source descriptor away from 0-4 so the dup2 actions cannot clobber it.
    return fcntl(fd, F_DUPFD_CLOEXEC, 10);
}

int vpn_spawn_supervisor(const char *supervisor, char *const arguments[], char *const environment[],
                         int config_fd, int cookie_fd, pid_t *pid) {
    if (!supervisor || !arguments || !arguments[0] || !environment || config_fd < 0 || !pid) { errno = EINVAL; return -1; }
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair)) return -1;
    fcntl(pair[0], F_SETFD, FD_CLOEXEC);
    fcntl(pair[1], F_SETFD, FD_CLOEXEC);
    int config = high_copy(config_fd);
    int cookie = cookie_fd >= 0 ? high_copy(cookie_fd) : -1;
    int child_end = high_copy(pair[1]);
    close(pair[1]);
    if (config < 0 || child_end < 0 || (cookie_fd >= 0 && cookie < 0)) {
        int saved = errno;
        if (config >= 0) close(config);
        if (cookie >= 0) close(cookie);
        if (child_end >= 0) close(child_end);
        close(pair[0]);
        errno = saved ? saved : EBADF;
        return -1;
    }
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, child_end, 0);
    posix_spawn_file_actions_adddup2(&actions, child_end, 1);
    posix_spawn_file_actions_adddup2(&actions, child_end, 2);
    posix_spawn_file_actions_adddup2(&actions, config, 3);
    if (cookie >= 0) posix_spawn_file_actions_adddup2(&actions, cookie, 4);
    posix_spawnattr_t attributes;
    posix_spawnattr_init(&attributes);
    sigset_t empty, defaults;
    sigemptyset(&empty);
    sigfillset(&defaults);
    posix_spawnattr_setsigmask(&attributes, &empty);
    posix_spawnattr_setsigdefault(&attributes, &defaults);
    posix_spawnattr_setpgroup(&attributes, 0);
    posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF |
                                          POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_CLOEXEC_DEFAULT);
    pid_t spawned = 0;
    int status = posix_spawn(&spawned, supervisor, &actions, &attributes, arguments, environment);
    posix_spawnattr_destroy(&attributes);
    posix_spawn_file_actions_destroy(&actions);
    close(config);
    if (cookie >= 0) close(cookie);
    close(child_end);
    if (status) { close(pair[0]); errno = status; return -1; }
    *pid = spawned;
    return pair[0];
}

int vpn_run_probe(const char *path, char *const arguments[], char *const environment[],
                  uid_t uid, gid_t gid, int timeout_ms,
                  char *output, size_t capacity, size_t *length, int *status) {
    if (!path || !arguments || !environment || !output || !length || !status || timeout_ms <= 0) { errno = EINVAL; return -1; }
    *length = 0;
    int channel[2];
    if (pipe(channel)) return -1;
    fcntl(channel[0], F_SETFD, FD_CLOEXEC);
    int null_input = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (null_input < 0) { close(channel[0]); close(channel[1]); return -1; }
    int drop = uid != (uid_t)-1 && gid != (gid_t)-1 && geteuid() == 0;
    pid_t child = fork();
    if (child < 0) { int saved = errno; close(channel[0]); close(channel[1]); close(null_input); errno = saved; return -1; }
    if (child == 0) {
        if (setpgid(0, 0) != 0) _exit(126);
        sigset_t empty;
        sigemptyset(&empty);
        sigprocmask(SIG_SETMASK, &empty, NULL);
        for (int number = 1; number < NSIG; ++number) signal(number, SIG_DFL);
        if (dup2(null_input, 0) < 0 || dup2(channel[1], 1) < 0 || dup2(channel[1], 2) < 0) _exit(126);
        int maximum = getdtablesize();
        for (int fd = 3; fd < maximum; ++fd) close(fd);
        if (drop) {
            if (setgroups(1, &gid) || setgid(gid) || setuid(uid)) _exit(126);
            if (getuid() != uid || geteuid() != uid || setuid(0) == 0) _exit(126);
        }
        execve(path, arguments, environment);
        _exit(127);
    }
    (void)setpgid(child, child);
    close(channel[1]);
    close(null_input);
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    int terminated = 0, killed = 0, open_channel = 1;
    for (;;) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed = (long)((now.tv_sec - start.tv_sec) * 1000 + (now.tv_nsec - start.tv_nsec) / 1000000);
        if (!terminated && elapsed >= timeout_ms) { kill(-child, SIGTERM); terminated = 1; }
        if (terminated && !killed && elapsed >= timeout_ms + 1000) { kill(-child, SIGKILL); killed = 1; open_channel = 0; }
        if (!open_channel) {
            pid_t done = waitpid(child, status, WNOHANG);
            if (done == child) break;
            if (done < 0 && errno != EINTR) { close(channel[0]); return -1; }
            struct timespec pause = { 0, 20 * 1000000 };
            nanosleep(&pause, NULL);
            continue;
        }
        struct pollfd descriptor = { .fd = channel[0], .events = POLLIN | POLLHUP };
        int ready = poll(&descriptor, 1, 100);
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0) continue;
        char buffer[4096];
        ssize_t count = read(channel[0], buffer, sizeof(buffer));
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { open_channel = 0; continue; }
        size_t room = capacity > *length ? capacity - *length : 0;
        size_t copy = (size_t)count < room ? (size_t)count : room;
        memcpy(output + *length, buffer, copy);
        *length += copy;
    }
    close(channel[0]);
    if (terminated) { errno = ETIMEDOUT; return -1; }
    return 0;
}

int vpn_process_start_time(pid_t pid, uint64_t *seconds, uint64_t *microseconds) {
    if (pid <= 0 || !seconds || !microseconds) { errno = EINVAL; return -1; }
    struct proc_bsdinfo info;
    int size = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info));
    if (size != (int)sizeof(info)) { if (!errno) errno = ESRCH; return -1; }
    *seconds = info.pbi_start_tvsec;
    *microseconds = info.pbi_start_tvusec;
    return 0;
}

int vpn_reserve_port(int *port) {
    if (!port || *port < 0 || *port > 65535) { errno = EINVAL; return -1; }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    // Match the client's restart semantics: an old accepted callback may be in
    // TIME_WAIT even though no authentication server is listening anymore.
    int reuse = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse))) {
        int saved = errno; close(fd); errno = saved; return -1;
    }
    struct sockaddr_in address = {0};
    address.sin_len = sizeof(address);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons((uint16_t)*port);
    // listen also proves exclusivity: two SO_REUSEADDR sockets may both bind
    // before either listens. Never enable SO_REUSEPORT or share a live callback.
    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) || listen(fd, 1)) {
        int saved = errno; close(fd); errno = saved; return -1;
    }
    socklen_t length = sizeof(address);
    if (getsockname(fd, (struct sockaddr *)&address, &length)) { close(fd); return -1; }
    *port = ntohs(address.sin_port);
    return fd;
}

// Exported by libsystem_sandbox (part of libSystem); not in the public SDK headers.
extern int sandbox_check(pid_t pid, const char *operation, int type, ...);

int vpn_is_sandboxed(void) {
    return sandbox_check(getpid(), NULL, 0) == 1;
}
