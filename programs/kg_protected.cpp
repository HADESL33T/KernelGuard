#include <iostream>
#include <fstream>
#include <thread>
#include <vector>
#include <string>
#include <chrono>
#include <ctime>
#include <cstdio>
#include <cstring>
#include <unistd.h>

using namespace std;

#define RED     "\033[1;31m"
#define YELLOW  "\033[1;33m"
#define CYAN    "\033[1;36m"
#define DIM     "\033[2;37m"
#define RESET   "\033[0m"

#define W 72

vector<string> threat_log;
bool running = true;

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

void top()  { printf(RED  "+%s+\n" RESET, string(W+2, '=').c_str()); }
void bot()  { printf(RED  "+%s+\n" RESET, string(W+2, '=').c_str()); }
void sep()  { printf(DIM  "+%s+\n" RESET, string(W+2, '-').c_str()); }
void row(const string& s, const char* color = "") {
    printf("%s| %s |\n%s", color, pad(s, W).c_str(), RESET);
}
void blank() { row(""); }

void read_dmesg() {
    FILE* pipe = popen("dmesg -w 2>/dev/null", "r");
    if (!pipe) return;
    char buffer[512];
    while (running && fgets(buffer, sizeof(buffer), pipe)) {
        string line(buffer);
        if (!line.empty() && line.back() == '\n') line.pop_back();
        if (line.find("[KERNELGUARD]") != string::npos) {
            size_t pos = line.find("[KERNELGUARD]");
            string msg = line.substr(pos);
            if (msg.size() > (size_t)W-10) msg = msg.substr(0, W-13) + "...";
            threat_log.push_back("[" + get_time() + "] " + msg);
        }
    }
    pclose(pipe);
}

void draw_screen() {
    while (running) {
        printf("\033[2J\033[1;1H");
        fflush(stdout);

        printf(RED);
        top();
        row("");
        row("                           核  心  守  卫                           ");
        row("                            KG - PROTECT                            ");
        row("");
        row("              Kernel-level Process Protection System                ");
        row("");
        printf(RESET);
        sep();

        char buf[W+1];
        snprintf(buf, sizeof(buf), "PID    : %d", getpid());
        row(buf, CYAN);
        row("Status : [#] KERNEL PROTECTED -!", RED);
        snprintf(buf, sizeof(buf), "Time   : %s", get_time().c_str());
        row(buf, CYAN);

        sep();
        row("  [!] THREAT LOG", YELLOW);
        sep();

        if (threat_log.empty()) {
            blank();
            row("  No threats detected...", DIM);
            blank();
            blank();
            blank();
            blank();
            blank();
            blank();
        } else {
            int start = max(0, (int)threat_log.size() - 8);
            for (int i = start; i < (int)threat_log.size(); i++) {
                string entry = "  [!!] " + threat_log[i];
                row(entry, RED);
            }
            int shown = (int)threat_log.size() - start;
            for (int i = shown; i < 8; i++) blank();
        }

        bot();
        printf(DIM "  Press Ctrl+C to exit\n" RESET);
        fflush(stdout);

        this_thread::sleep_for(chrono::seconds(1));
    }
}

int main() {
    thread t1(read_dmesg);
    thread t2(draw_screen);
    t1.join();
    t2.join();
    return 0;
}
