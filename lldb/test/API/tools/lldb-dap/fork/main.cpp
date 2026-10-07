#include "attach.h"
#include <cassert>
#include <csignal>
#include <cstring>
#include <fstream>
#include <string>
#include <sys/wait.h>
#include <unistd.h>

void before_fork() {}
void parent_breakpoint() {}
void child_breakpoint() {}

int fork_from_expression() {
  pid_t child = fork();
  if (child == 0)
    _exit(0);
  int status;
  assert(waitpid(child, &status, 0) == child);
  return 42;
}

static void child_code(const char *marker, bool nested) {
  std::ofstream(std::string(marker) + "." + std::to_string(getpid())).close();
  if (nested) {
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0)
      child_code(marker, false);
    int status;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 47);
  }
  child_breakpoint();
  _exit(47);
}

int main(int argc, char **argv) {
  assert(argc == 3);
  lldb_enable_attach();
  if (strcmp(argv[1], "attach-fork") == 0)
    raise(SIGSTOP);
  if (strcmp(argv[1], "stopped") == 0) {
    raise(SIGSTOP);
    child_code(argv[2], false);
  }
  // Restart intentionally kills the parent. Let the resumed former
  // child finish even if its process group becomes orphaned at that point.
  if (strcmp(argv[1], "restart") == 0)
    signal(SIGHUP, SIG_IGN);
  const bool is_vfork = strcmp(argv[1], "vfork") == 0;
  const bool nested = strcmp(argv[1], "nested") == 0;
  before_fork();
  pid_t child = is_vfork ? vfork() : fork();
  assert(child >= 0);
  if (child == 0) {
    if (is_vfork)
      _exit(47);
    child_code(argv[2], nested);
  }
  parent_breakpoint();
  int status;
  assert(waitpid(child, &status, 0) == child);
  assert(WIFEXITED(status) && WEXITSTATUS(status) == 47);
  return 0;
}
