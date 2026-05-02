#include <iostream>
#include <chrono>
#include <thread>
#include <ctime>
#include <cstdio>
#include <unistd.h>

using namespace std;

#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define CYAN    "\033[1;36m"
#define DIM     "\033[2;37m"
#define RESET   "\033[0m"

#define W 64

string get_time() {
    time_t now = time(0);
    tm* t = localtime(&now);
    char buf[16];
    sprintf(buf, "%02d:%02d:%02d", t->tm_hour, t->tm_min, t->tm_sec);
    return string(buf);
}

string pad(const string& s, int width) {
    if ((int)s.size() >= width) return s.substr(0, width);
    return s + string(width - s.size(), ' ');
}

void top()   { printf("+%s+\n", string(W+2, '=').c_str()); }
void bot()   { printf("+%s+\n", string(W+2, '=').c_str()); }
void sep()   { printf("+%s+\n", string(W+2, '-').c_str()); }
void row(const string& s, const char* color = "") {
    printf("%s| %s |\n%s", color, pad(s, W).c_str(), RESET);
}

int main() {
    int secret_value = 99999;
    while (true) {
        printf("\033[H\033[2J");
        fflush(stdout);

        printf(GREEN);
        top();
        row("  _   _  ___  ____  __  __    _    _                        ");
        row(" | \\ | |/ _ \\|  _ \\|  \\/  |  / \\  | |                       ");
        row(" |  \\| | | | | |_) | |\\/| | / _ \\ | |                       ");
        row(" | |\\  | |_| |  _ <| |  | |/ ___ \\| |___                    ");
        row(" |_| \\_|\\___/|_| \\_\\_|  |_/_/   \\_\\_____|                   ");
        printf(RESET);
        sep();

        char buf[W+1];
        snprintf(buf, sizeof(buf), "PID    : %d", getpid());
        row(buf, CYAN);
        row("Status : [!] UNPROTECTED -- Anyone can attach!", YELLOW);
        snprintf(buf, sizeof(buf), "Time   : %s", get_time().c_str());
        row(buf, CYAN);
        sep();
        snprintf(buf, sizeof(buf), "Secret Value : %d", secret_value);
        row(buf, GREEN);
        snprintf(buf, sizeof(buf), "Memory Addr  : %p", (void*)&secret_value);
        row(buf, GREEN);
        sep();
        row("  >> Try: sudo gdb -p <PID>  -- You CAN attach!", DIM);
        bot();

        printf(RESET);
        fflush(stdout);
        this_thread::sleep_for(chrono::seconds(1));
    }
    return 0;
}
