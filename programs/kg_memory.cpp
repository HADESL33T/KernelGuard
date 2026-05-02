#include <iostream>
#include <chrono>
#include <thread>
#include <ctime>
#include <cstdio>
#include <unistd.h>
#include <fstream>
#include <string>

using namespace std;

#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define CYAN    "\033[1;36m"
#define RED     "\033[1;31m"  // เพิ่มสีแดงสำหรับแจ้งเตือน
#define DIM     "\033[2;37m"
#define RESET   "\033[0m"

#define W 64

// ฟังก์ชันเช็คว่ามี Debugger เกาะอยู่ไหม
int get_tracer_pid() {
    ifstream status("/proc/self/status");
    string line;
    while (getline(status, line)) {
        if (line.find("TracerPid:") == 0) {
            return stoi(line.substr(10));
        }
    }
    return 0;
}

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
    int secret_value = 12345; // เปลี่ยนเลขตามที่คุณชอบ
    while (true) {
        int tracer = get_tracer_pid();
        printf("\033[H\033[2J");
        fflush(stdout);

        // เปลี่ยนสีหัวข้อตามสถานะ
        printf(tracer > 0 ? RED : GREEN);
        top();
        row("  _  _______   ____  ____   ___ _____ _____ ____ _____ ");
        row(" | |/ / ____| |  _ \\|  _ \\ / _ \\_   _| ____/ ___|_   _|");
        row(" | ' /|  _|   | |_) | |_) | | | || | |  _| \\___ \\ | |  ");
        row(" | . \\| |___  |  __/|  _ <| |_| || | | |___ ___) || |  ");
        row(" |_|\\_\\_____| |_|   |_| \\_\\\\___/ |_| |_____|____/ |_|  ");
        printf(RESET);
        sep();

        char buf[W+1];
        snprintf(buf, sizeof(buf), "PID    : %d", getpid());
        row(buf, CYAN);

        // แจ้งสถานะ ถ้าโดนเกาะให้ขึ้นสีแดง
        if (tracer > 0) {
            snprintf(buf, sizeof(buf), "Status : [!!!] INTRUDER DETECTED! (Tracer PID: %d)", tracer);
            row(buf, RED);
        } else {
            row("Status : [#] KERNEL PROTECTED! - Memory Cloaking Active", GREEN);
        }

        snprintf(buf, sizeof(buf), "Time   : %s", get_time().c_str());
        row(buf, CYAN);
        sep();

        // ส่วนที่แสดงค่าลับ (ใน PINCE จะเห็นเป็นเลขสุ่ม แต่ในจอนี้จะนิ่ง)
        snprintf(buf, sizeof(buf), "Secret Value : %d", secret_value);
        row(buf, (tracer > 0 ? YELLOW : GREEN));
        snprintf(buf, sizeof(buf), "Memory Addr  : %p", (void*)&secret_value);
        row(buf, (tracer > 0 ? YELLOW : GREEN));
        sep();

        if (tracer > 0) {
            row("  >> THREAT: Someone is trying to debug this process!", RED);
        } else {
            row("  >> System Secure. Kernel is feeding noise to debuggers.", DIM);
        }
        bot();

        printf(RESET);
        fflush(stdout);
        this_thread::sleep_for(chrono::milliseconds(500)); // ให้มัน Refresh ไวขึ้นหน่อย
    }
    return 0;
}
