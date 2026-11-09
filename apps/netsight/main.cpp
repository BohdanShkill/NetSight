#include "App.hpp"
#include "Signals.hpp"

#ifdef _WIN32
#include <cstdio>
#include <io.h>
#else
#include <unistd.h>
#endif

int main(int argc, char* argv[]) {
    netsight::SignalGuard signal_guard;

    netsight::AppEnv env{};
#ifdef _WIN32
    env.stdin_is_tty = (_isatty(_fileno(stdin)) != 0);
    env.stdout_is_tty = (_isatty(_fileno(stdout)) != 0);
#else
    env.stdin_is_tty = (isatty(STDIN_FILENO) != 0);
    env.stdout_is_tty = (isatty(STDOUT_FILENO) != 0);
#endif

    return static_cast<int>(netsight::run_netsight(argc, argv, env));
}