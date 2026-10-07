#include <assert.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
  if (argc != 2) {
    _exit(1);
  }
  // break here
  pid_t pid = strcmp(argv[1], "fork") == 0 ? fork() : vfork();
  if (pid == 0) {
    // child
    _exit(47);
  }
  // parent
  int status;
  assert(waitpid(pid, &status, 0) == pid);
  assert(WIFEXITED(status) && WEXITSTATUS(status) == 47);
  _exit(0);
}
