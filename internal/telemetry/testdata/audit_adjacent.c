#define _GNU_SOURCE
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <netinet/in.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

static volatile sig_atomic_t trapped;
static void trap(int sig, siginfo_t *info, void *context) {
  (void)sig;
  (void)info;
  trapped = 1;
  ucontext_t *u = context;
#if defined(__aarch64__)
  u->uc_mcontext.regs[0] = (unsigned long)-ENOSYS;
#elif defined(__x86_64__)
  u->uc_mcontext.gregs[REG_RAX] = -ENOSYS;
#else
#error unsupported architecture
#endif
}

int main(int argc, char **argv) {
  if (argc != 3) return 2;
  uint32_t action;
  if (!strcmp(argv[1], "ERRNO")) action = SECCOMP_RET_ERRNO | EPERM;
  else if (!strcmp(argv[1], "KILL_PROCESS")) action = SECCOMP_RET_KILL_PROCESS;
  else if (!strcmp(argv[1], "KILL_THREAD")) action = SECCOMP_RET_KILL_THREAD;
  else if (!strcmp(argv[1], "TRAP")) action = SECCOMP_RET_TRAP;
  else if (!strcmp(argv[1], "TRACE")) action = SECCOMP_RET_TRACE;
  else if (!strcmp(argv[1], "USER_NOTIF")) action = SECCOMP_RET_USER_NOTIF;
  else if (!strcmp(argv[1], "LOG")) action = SECCOMP_RET_LOG;
  else return 2;
  struct rlimit limit = {0, 0};
  if (setrlimit(RLIMIT_CORE, &limit)) return 3;
  struct sigaction handler = {.sa_sigaction = trap, .sa_flags = SA_SIGINFO};
  sigemptyset(&handler.sa_mask);
  if (sigaction(SIGSYS, &handler, NULL)) return 3;
  int listener = socket(AF_INET, SOCK_STREAM, 0);
  int allowed = socket(AF_INET, SOCK_STREAM, 0);
  int blocked = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in target = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
  socklen_t length = sizeof(target);
  if (listener < 0 || allowed < 0 || blocked < 0 ||
      bind(listener, (void *)&target, length) || listen(listener, 4) ||
      getsockname(listener, (void *)&target, &length)) return 3;
  // Only one descriptor is filtered; the adjacent call uses the same syscall,
  // process, thread and destination but really succeeds.
  struct sock_filter insns[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
#if defined(__aarch64__)
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 1, 0),
#elif defined(__x86_64__)
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
#endif
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_connect, 0, 3),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)blocked, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, action),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };
  struct sock_fprog filter = {.len = sizeof(insns) / sizeof(insns[0]), .filter = insns};
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
      syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_LOG, &filter)) return 4;
  printf("{\"pid\":%d,\"tid\":%ld,\"syscall_number\":%d,\"action\":%u,\"port\":%u}\n",
         getpid(), syscall(SYS_gettid), SYS_connect, action, ntohs(target.sin_port));
  fflush(stdout);
  if (getchar() == EOF) return 5;
  usleep(30000);
  for (int i = 0; i < 2; i++) {
    int deny = !strcmp(argv[2], "deny-first") ? i == 0 : i == 1;
    struct timespec at;
    clock_gettime(CLOCK_REALTIME, &at);
    errno = 0;
    long result = syscall(SYS_connect, deny ? blocked : allowed, &target, length);
    int error = errno;
    printf("{\"filtered\":%s,\"result\":%ld,\"errno\":%d,\"trapped\":%d,\"time_ns\":%lld}\n",
           deny ? "true" : "false", result, error, trapped,
           (long long)at.tv_sec * 1000000000LL + at.tv_nsec);
    fflush(stdout);
  }
  usleep(30000);
  return 0;
}
