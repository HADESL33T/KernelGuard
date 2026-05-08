// kg_normal.cpp — KernelGuard: unprotected process demo
// No kernel interaction; shows real secret_value and stack address.

#include <SDL2/SDL.h>
#include <GL/gl.h>
#include "imgui.h"
#include "imgui_impl_sdl2.h"
#include "imgui_impl_opengl3.h"

#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>
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

int main() {
    const pid_t own_pid = getpid();

    volatile int secret_value = 0xDEADBEEF;
    const void* secret_addr   = (const void*)&secret_value;

    // ── SDL + GL ──────────────────────────────────────────────────────────────
    SDL_Init(SDL_INIT_VIDEO);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);

    SDL_Window* window = SDL_CreateWindow(
        "KernelGuard — Normal",
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
    ImGuiStyle& style               = ImGui::GetStyle();
    style.WindowBorderSize          = 1.f;
    style.FrameBorderSize           = 1.f;
    style.Colors[ImGuiCol_WindowBg] = COL_BG;
    style.Colors[ImGuiCol_Border]   = COL_BORDER;
    style.Colors[ImGuiCol_ChildBg]  = COL_PANEL;

    ImGui_ImplSDL2_InitForOpenGL(window, gl_ctx);
    ImGui_ImplOpenGL3_Init("#version 330");

    // ── State ─────────────────────────────────────────────────────────────────
    std::vector<LogEntry> log;
    const Uint64 start_ticks = SDL_GetTicks64();
    bool scroll_to_bottom    = false;

    log.push_back({now_str(), "Process started — no protection active", COL_INFO});
    log.push_back({now_str(), "Attach/read events will appear here",    COL_INFO});

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

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplSDL2_NewFrame();
        ImGui::NewFrame();

        int win_w, win_h;
        SDL_GetWindowSize(window, &win_w, &win_h);
        const float W = (float)win_w;
        const float H = (float)win_h;

        ImGui::SetNextWindowPos({0, 0});
        ImGui::SetNextWindowSize({W, H});
        ImGui::Begin("##main", nullptr,
            ImGuiWindowFlags_NoResize   | ImGuiWindowFlags_NoMove |
            ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar);

        // Title
        ImGui::TextColored(COL_OK,  "KernelGuard v1.0");
        ImGui::SameLine();
        ImGui::TextColored(COL_DIM, "— Normal Process Demo");
        ImGui::Separator();

        // Badge
        ImGui::TextColored(COL_OK, "[!] UNPROTECTED — anyone can attach");
        ImGui::Separator();

        // Stats row
        const float  box_w  = (ImGui::GetContentRegionAvail().x - 16.f) / 3.f;
        const Uint64 uptime = (SDL_GetTicks64() - start_ticks) / 1000;

        auto stat_box = [&](const char* label, const char* value, ImVec4 vcol) {
            ImGui::BeginChild(label, {box_w, 52.f}, true);
            ImGui::TextColored(COL_DIM, "%s", label);
            ImGui::TextColored(vcol,    "%s", value);
            ImGui::EndChild();
        };

        char pid_str[32], up_str[32];
        snprintf(pid_str, sizeof(pid_str), "%d",    own_pid);
        snprintf(up_str,  sizeof(up_str),  "%llus", (unsigned long long)uptime);

        stat_box("PID",     pid_str, COL_AMBER);
        ImGui::SameLine();
        stat_box("Uptime",  up_str,  COL_TEXT);
        ImGui::SameLine();
        stat_box("Threats", "0",     COL_OK);
        ImGui::Separator();

        // Log panel
        ImGui::TextColored(COL_DIM, "Activity Log");
        ImGui::BeginChild("##log", {0, H * 0.35f}, true);
        for (const auto& e : log) {
            ImGui::TextColored(COL_DIM, "[%s] ", e.timestamp.c_str());
            ImGui::SameLine();
            ImGui::TextColored(e.color, "%s",    e.message.c_str());
        }
        if (scroll_to_bottom) { ImGui::SetScrollHereY(1.f); scroll_to_bottom = false; }
        ImGui::EndChild();
        ImGui::Separator();

        // Memory panel
        ImGui::TextColored(COL_DIM, "Memory View");
        if (ImGui::BeginTable("##mem", 3,
                ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
            ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed,   120.f);
            ImGui::TableSetupColumn("Hex",     ImGuiTableColumnFlags_WidthFixed,   150.f);
            ImGui::TableSetupColumn("Decoded", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();

            // Row 1: secret_value
            {
                const auto* raw = (const unsigned char*)&secret_value;
                char hex[32], dec[32];
                snprintf(hex, sizeof(hex), "%02x %02x %02x %02x",
                         raw[0], raw[1], raw[2], raw[3]);
                snprintf(dec, sizeof(dec), "0x%08X", (unsigned)secret_value);
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::TextColored(COL_ADDR, "0x%014llx",
                    (unsigned long long)(uintptr_t)secret_addr);
                ImGui::TableSetColumnIndex(1);
                ImGui::TextColored(COL_DIM, "%s", hex);
                ImGui::TableSetColumnIndex(2);
                ImGui::TextColored(COL_OK,  "%s", dec);
            }

            // Row 2: stack frame pointer
            {
                void* fp        = __builtin_frame_address(0);
                const auto* raw = (const unsigned char*)&fp;
                char hex[64];
                int n = 0;
                for (int i = 0; i < (int)sizeof(fp); i++)
                    n += snprintf(hex + n, (int)sizeof(hex) - n, "%02x ", raw[i]);
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::TextColored(COL_ADDR, "0x%014llx",
                    (unsigned long long)(uintptr_t)fp);
                ImGui::TableSetColumnIndex(1);
                ImGui::TextColored(COL_DIM, "%s", hex);
                ImGui::TableSetColumnIndex(2);
                ImGui::TextColored(COL_OK,  "(stack ptr)");
            }

            // Row 3: null sentinel
            {
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::TextColored(COL_ADDR, "0x%014llx", 0ULL);
                ImGui::TableSetColumnIndex(1);
                ImGui::TextColored(COL_DIM,  "00 00 00 00");
                ImGui::TableSetColumnIndex(2);
                ImGui::TextColored(COL_DIM,  "(null)");
            }

            ImGui::EndTable();
        }
        ImGui::Separator();

        // Footer
        if (ImGui::Button("Clear log")) { log.clear(); scroll_to_bottom = true; }
        ImGui::SameLine();
        if (ImGui::Button("Export"))    { export_log(log, own_pid); }
        ImGui::SameLine();
        ImGui::TextColored(COL_DIM, "  Ctrl+C to exit");

        ImGui::End();

        ImGui::Render();
        glViewport(0, 0, win_w, win_h);
        glClearColor(COL_BG.x, COL_BG.y, COL_BG.z, 1.f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        SDL_GL_SwapWindow(window);
    }

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplSDL2_Shutdown();
    ImGui::DestroyContext();
    SDL_GL_DeleteContext(gl_ctx);
    SDL_DestroyWindow(window);
    SDL_Quit();
    return 0;
}
