#include "attach.h"
#include "pseudo_barrier.h"
#include <cassert>
#include <chrono>
#include <cstring>
#include <fstream>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

static pseudo_barrier_t barrier;

volatile bool start = false;

void before_detach() {}

static void write_marker(const char *path) { std::ofstream(path).close(); }

int main(int argc, char **argv) {
  assert(argc >= 3);
  lldb_enable_attach();
  const char *mode = argv[1];
  const char *marker = argv[2];
  if (strcmp(mode, "after-exec") == 0) {
    write_marker(marker);
    return 0;
  }
  if (argc == 4) {
    write_marker(argv[3]);
    while (!start)
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  if (strcmp(mode, "threads") == 0) {
    constexpr unsigned count = 5;
    pseudo_barrier_init(barrier, count);
    std::vector<std::thread> threads;
    for (unsigned i = 0; i < count; ++i) {
      threads.emplace_back([marker] {
        pseudo_barrier_wait(barrier);
        before_detach();
        write_marker(marker);
      });
    }
    for (auto &thread : threads)
      thread.join();
    return 0;
  }
  before_detach();
  if (strcmp(mode, "fork") == 0 || strcmp(mode, "vfork") == 0) {
    pid_t child = strcmp(mode, "fork") == 0 ? fork() : vfork();
    assert(child >= 0);
    if (child == 0)
      _exit(0);
    int status;
    assert(waitpid(child, &status, 0) == child);
  } else if (strcmp(mode, "exec") == 0) {
    execl(argv[0], argv[0], "after-exec", marker, nullptr);
    _exit(1);
  }
  write_marker(marker);
  return 0;
}
