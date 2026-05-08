// kg_protected.cpp — KernelGuard: kernel-protected process demo
// Background thread reads `dmesg -w`, filters [KERNELGUARD] lines for own PID.
// Render thread is lock-guarded via std::mutex.

#include <SDL2/SDL.h>
#include <GL/gl.h>
#include "imgui.h"
#include "imgui_impl_sdl2.h"
#include "imgui_impl_opengl3.h"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <unistd.h>

// ── Color palette ─────────────────────────────────────────────────────────────
static constexpr ImVec4 COL_BG     = {0.094f, 0.094f, 0.094f, 1.f};
static constexpr ImVec4 COL_PANEL  = {0.067f, 0.067f, 0.067f, 1.f};
static constexpr ImVec4 COL_BORDER = {0.180f, 0.180f, 0.180f, 1.f};
static constexpr ImVec4 COL_TEXT   = {0.667f, 0.667f, 0.667f, 1.f};
static constexpr ImVec4 COL_ADDR   = {0.267f, 0.533f, 0.800f, 1.f};
static constexpr ImVec4 COL_OK     = {0.314f, 0.800f, 0.400f, 1.f};
static constexpr ImVec4 COL_THREAT = {0.878f, 0.314f, 0.314f, 1.f};
static constexpr ImVec4 COL_DIM    = {0.267f, 0.267f, 0.267f, 1.f};
static constexpr ImVec4 COL_AMBER  = {0.800f, 0.600f, 0.251f, 1.f};
static constexpr ImVec4 COL_INFO   = {0.267f, 0.533f, 0.900f, 1.f};

struct LogEntry {
    std::string timestamp;
    std::string message;
    ImVec4      color;
};

static std::string now_str() {
    time_t t = time(nullptr);
    struct tm tm{};
    localtime_r(&t, &tm);
    char buf[32];
    snprintf(buf, sizeof(buf), "%02d:%02d:%02d", tm.tm_hour, tm.tm_min, tm.tm_sec);
    return buf;
}

static void export_log(const std::vector<LogEntry>& log, pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "kg_export_%d.txt", pid);
    FILE* f = fopen(path, "w");
    if (!f) return;
    for (const auto& e : log)
        fprintf(f, "[%s] %s\n", e.timestamp.c_str(), e.message.c_str());
    fclose(f);
}

// ── dmesg reader thread ───────────────────────────────────────────────────────
// Appends matching [KERNELGUARD] lines into shared threat_log under mutex.
static void read_dmesg(
    pid_t                  own_pid,
    std::vector<LogEntry>& threat_log,
    std::mutex&            log_mutex,
    std::atomic<bool>&     running,
    std::atomic<bool>&     new_entries)
{
    // Build the PID filter string once
    char pid_filter[64];
    snprintf(pid_filter, sizeof(pid_filter), "protected process PID %d", own_pid);

    FILE* pipe = popen("dmesg -w", "r");
    if (!pipe) return;

    char line[1024];
    while (running.load() && fgets(line, sizeof(line), pipe)) {
        // Must contain both markers
        if (strstr(line, "[KERNELGUARD]") && strstr(line, pid_filter)) {
            // Strip trailing newline
            size_t len = strlen(line);
            if (len > 0 && line[len - 1] == '\n') line[len - 1] = '\0';

            std::lock_guard<std::mutex> lk(log_mutex);
            threat_log.push_back({now_str(), std::string(line), COL_THREAT});
            new_entries.store(true);
        }
    }
    pclose(pipe);
}

int main() {
    const pid_t own_pid = getpid();

    // ── SDL + GL ──────────────────────────────────────────────────────────────
    SDL_Init(SDL_INIT_VIDEO);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);

    SDL_Window* window = SDL_CreateWindow(
        "KernelGuard — Protected",
        SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
        900, 620, SDL_WINDOW_OPENGL | SDL_WINDOW_SHOWN | SDL_WINDOW_RESIZABLE);
    SDL_GLContext gl_ctx = SDL_GL_CreateContext(window);
    SDL_GL_MakeCurrent(window, gl_ctx);
    SDL_GL_SetSwapInterval(1);

    // ── ImGui ─────────────────────────────────────────────────────────────────
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = nullptr;

    if (!io.Fonts->AddFontFromFileTTF("Cousine-Regular.ttf", 13.f))
        io.Fonts->AddFontDefault();

    ImGui::StyleColorsDark();
    ImGuiStyle& style          = ImGui::GetStyle();
    style.WindowBorderSize     = 1.f;
    style.FrameBorderSize      = 1.f;
    style.Colors[ImGuiCol_WindowBg] = COL_BG;
    style.Colors[ImGuiCol_Border]   = COL_BORDER;
    style.Colors[ImGuiCol_ChildBg]  = COL_PANEL;

    ImGui_ImplSDL2_InitForOpenGL(window, gl_ctx);
    ImGui_ImplOpenGL3_Init("#version 330");

    // ── Shared state ──────────────────────────────────────────────────────────
    std::vector<LogEntry> threat_log;
    std::mutex            log_mutex;
    std::atomic<bool>     dmesg_running{true};
    std::atomic<bool>     new_entries{false};

    const Uint64 start_ticks  = SDL_GetTicks64();
    bool scroll_to_bottom     = false;

    // Seed log
    {
        std::lock_guard<std::mutex> lk(log_mutex);
        threat_log.push_back({now_str(), "Kernel protection active — monitoring dmesg", COL_INFO});
    }

    // Start background dmesg reader
    std::thread dmesg_thread(read_dmesg,
        own_pid,
        std::ref(threat_log),
        std::ref(log_mutex),
        std::ref(dmesg_running),
        std::ref(new_entries));

    // ── Render loop ───────────────────────────────────────────────────────────
    bool running = true;
    while (running) {
        SDL_Event ev;
        while (SDL_PollEvent(&ev)) {
            ImGui_ImplSDL2_ProcessEvent(&ev);
            if (ev.type == SDL_QUIT) running = false;
            if (ev.type == SDL_KEYDOWN &&
                ev.key.keysym.sym == SDLK_c &&
                (SDL_GetModState() & KMOD_CTRL))
                running = false;
        }

        // Check if background thread pushed new entries
        if (new_entries.exchange(false))
            scroll_to_bottom = true;

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplSDL2_NewFrame();
        ImGui::NewFrame();

        int win_w, win_h;
        SDL_GetWindowSize(window, &win_w, &win_h);
        const float W = (float)win_w;
        const float H = (float)win_h;

        // Snapshot log under lock for rendering
        std::vector<LogEntry> render_log;
        size_t threat_count = 0;
        {
            std::lock_guard<std::mutex> lk(log_mutex);
            render_log    = threat_log;
            // Count actual threat lines (skip the seed info line)
            for (const auto& e : threat_log)
                if (e.color.x == COL_THREAT.x) ++threat_count;
        }

        ImGui::SetNextWindowPos({0, 0});
        ImGui::SetNextWindowSize({W, H});
        ImGui::Begin("##main", nullptr,
            ImGuiWindowFlags_NoResize   | ImGuiWindowFlags_NoMove |
            ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar);

        // Title
        ImGui::TextColored(COL_THREAT, "KernelGuard v1.0");
        ImGui::SameLine();
        ImGui::TextColored(COL_DIM, "— Protected Process");
        ImGui::Separator();

        // Badge
        ImGui::TextColored(COL_THREAT, "[#] KERNEL PROTECTED");
        ImGui::Separator();

        // Stats row
        const float box_w   = (ImGui::GetContentRegionAvail().x - 16.f) / 3.f;
        const Uint64 uptime = (SDL_GetTicks64() - start_ticks) / 1000;

        auto stat_box = [&](const char* label, const char* value, ImVec4 vcol) {
            ImGui::BeginChild(label, {box_w, 52.f}, true);
            ImGui::TextColored(COL_DIM, "%s", label);
            ImGui::TextColored(vcol,    "%s", value);
            ImGui::EndChild();
        };

        char pid_str[32], up_str[32], threat_str[32];
        snprintf(pid_str,    sizeof(pid_str),    "%d",    own_pid);
        snprintf(up_str,     sizeof(up_str),     "%llus", (unsigned long long)uptime);
        snprintf(threat_str, sizeof(threat_str), "%zu",   threat_count);

        stat_box("PID",     pid_str,    COL_AMBER);
        ImGui::SameLine();
        stat_box("Uptime",  up_str,     COL_TEXT);
        ImGui::SameLine();
        stat_box("Threats", threat_str, threat_count > 0 ? COL_THREAT : COL_OK);
        ImGui::Separator();

        // Log panel
        ImGui::TextColored(COL_DIM, "Threat Log  [KERNELGUARD]");
        ImGui::BeginChild("##log", {0, H * 0.35f}, true);
        for (const auto& e : render_log) {
            ImGui::TextColored(COL_DIM,  "[%s] ", e.timestamp.c_str());
            ImGui::SameLine();
            ImGui::TextColored(e.color,  "%s",    e.message.c_str());
        }
        if (scroll_to_bottom) { ImGui::SetScrollHereY(1.f); scroll_to_bottom = false; }
        ImGui::EndChild();
        ImGui::Separator();

        // Memory panel — zeroed/noise (kernel blocks real reads)
        ImGui::TextColored(COL_DIM, "Memory View  (kernel-blocked)");
        if (ImGui::BeginTable("##mem", 3,
                ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
            ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed,   120.f);
            ImGui::TableSetupColumn("Hex",     ImGuiTableColumnFlags_WidthFixed,   150.f);
            ImGui::TableSetupColumn("Decoded", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();

            // All three rows show zeroed bytes — kernel blocked the read
            for (int row = 0; row < 3; ++row) {
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::TextColored(COL_ADDR, "0x%014llx", 0ULL);
                ImGui::TableSetColumnIndex(1);
                ImGui::TextColored(COL_DIM,  "00 00 00 00");
                ImGui::TableSetColumnIndex(2);
                ImGui::TextColored(COL_DIM,  "????????");
            }

            ImGui::EndTable();
        }
        ImGui::Separator();

        // Footer
        if (ImGui::Button("Clear log")) {
            std::lock_guard<std::mutex> lk(log_mutex);
            threat_log.clear();
            scroll_to_bottom = true;
        }
        ImGui::SameLine();
        if (ImGui::Button("Export")) {
            std::lock_guard<std::mutex> lk(log_mutex);
            export_log(threat_log, own_pid);
        }
        ImGui::SameLine();
        ImGui::TextColored(COL_DIM, "  Ctrl+C to exit");

        ImGui::End();

        // Draw
        ImGui::Render();
        glViewport(0, 0, win_w, win_h);
        glClearColor(COL_BG.x, COL_BG.y, COL_BG.z, 1.f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        SDL_GL_SwapWindow(window);
    }

    // Signal dmesg thread to stop and detach (pclose will unblock it)
    dmesg_running.store(false);
    dmesg_thread.detach();

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplSDL2_Shutdown();
    ImGui::DestroyContext();
    SDL_GL_DeleteContext(gl_ctx);
    SDL_DestroyWindow(window);
    SDL_Quit();
    return 0;
}
