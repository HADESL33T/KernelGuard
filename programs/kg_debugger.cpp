// kg_debugger.cpp — KernelGuard Demo Memory Inspector
// Style: Memory Viewer (x64dbg-style) + One Dark theme
// Two windows: Memory Viewer + KG Scanner
// Three read backends: process_vm_readv / /proc/PID/mem / ptrace
//
// Build:
//   cd ~/CS422/Project/Final/KernelGuard
//   g++ programs/kg_debugger.cpp -o build/kg_debugger \
//     imgui/imgui.cpp imgui/imgui_draw.cpp imgui/imgui_tables.cpp imgui/imgui_widgets.cpp \
//     imgui/backends/imgui_impl_sdl2.cpp imgui/backends/imgui_impl_opengl3.cpp \
//     $(sdl2-config --cflags --libs) -lGL -std=c++17 -lpthread -I.
//
// Run: sudo ./build/kg_debugger

#include <SDL2/SDL.h>
#include <GL/gl.h>
#include "imgui/imgui.h"
#include "imgui/backends/imgui_impl_sdl2.h"
#include "imgui/backends/imgui_impl_opengl3.h"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <dirent.h>
#include <fcntl.h>
#include <mutex>
#include <signal.h>
#include <string>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

// ─────────────────────────────────────────────────────────────────────────────
// One Dark palette
// ─────────────────────────────────────────────────────────────────────────────
namespace OD {
    static constexpr ImVec4 BG0    = {0.110f,0.118f,0.137f,1.f};
    static constexpr ImVec4 BG1    = {0.141f,0.149f,0.169f,1.f};
    static constexpr ImVec4 BG2    = {0.173f,0.184f,0.208f,1.f};
    static constexpr ImVec4 BORDER = {0.220f,0.231f,0.259f,1.f};
    static constexpr ImVec4 FG     = {0.788f,0.804f,0.839f,1.f};
    static constexpr ImVec4 DIM    = {0.400f,0.420f,0.467f,1.f};
    static constexpr ImVec4 RED    = {0.902f,0.361f,0.408f,1.f};
    static constexpr ImVec4 GREEN  = {0.608f,0.780f,0.447f,1.f};
    static constexpr ImVec4 YELLOW = {0.902f,0.780f,0.447f,1.f};
    static constexpr ImVec4 BLUE   = {0.373f,0.627f,0.918f,1.f};
    static constexpr ImVec4 CYAN   = {0.365f,0.773f,0.843f,1.f};
    static constexpr ImVec4 PURPLE = {0.753f,0.573f,0.918f,1.f};
    static constexpr ImVec4 ORANGE = {0.918f,0.600f,0.290f,1.f};
}

// ─────────────────────────────────────────────────────────────────────────────
// Structs & enums
// ─────────────────────────────────────────────────────────────────────────────
struct ProcessEntry { pid_t pid; std::string name; };

struct MemRegion {
    uintptr_t   start, end;
    char        perms[8];
    char        name[256];
};

struct ScanResult {
    uintptr_t address;
    int32_t   value;
    int32_t   prev_value;
};

struct AddrBookEntry {
    char      desc[64];
    uintptr_t address;
    int32_t   value;
    bool      frozen;
    int32_t   freeze_val;
};

enum ReadMethod { VM_READV=0, PROC_MEM=1, PTRACE_M=2 };
static const char* METHOD_NAMES[] = {"process_vm_readv","/proc/PID/mem","ptrace"};
static const char* SCAN_TYPES[]   = {"Exact Value","Changed","Unchanged","Increased","Decreased"};
static const char* VALUE_TYPES[]  = {"1 Byte","2 Bytes","4 Bytes","8 Bytes","Float","Double"};

// ─────────────────────────────────────────────────────────────────────────────
// Globals
// ─────────────────────────────────────────────────────────────────────────────
static pid_t              g_pid            = 0;
static bool               g_attached       = false;
static char               g_attach_err[256]= {};
static bool               g_suspended      = false;

static ReadMethod         g_method         = VM_READV;
static ReadMethod         g_settings_tmp   = VM_READV;

static std::vector<ProcessEntry>  g_procs;
static std::mutex                 g_procs_mtx;
static std::atomic<bool>          g_procs_dirty{true};

static std::vector<MemRegion>     g_regions;
static int                        g_region_sel = 0;

static std::vector<ScanResult>    g_results;
static std::mutex                 g_results_mtx;
static std::atomic<bool>          g_scanning{false};
static bool                       g_first_scan = true;
static int                        g_scan_type  = 0;
static int                        g_value_type = 2;
static char                       g_scan_input[32] = {};

static std::vector<AddrBookEntry> g_addrbook;

static uintptr_t          g_hex_addr  = 0;
static char               g_hex_input[32] = {};
static std::vector<uint8_t> g_hex_buf;
static std::mutex           g_hex_mtx;
static std::atomic<bool>    g_hex_live{false};

static char               g_proc_filter[64] = {};
static char               g_pid_input[16]   = {};
static int                g_proc_sel        = -1;

static char               g_mv_status[256] = "Ready";
static ImVec4             g_mv_col         = OD::DIM;
static char               g_sc_status[256] = "Ready";
static ImVec4             g_sc_col         = OD::DIM;

static bool               g_show_settings  = false;

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────
static void mv_status(const char* m, ImVec4 c=OD::DIM){ snprintf(g_mv_status,sizeof(g_mv_status),"%s",m); g_mv_col=c; }
static void sc_status(const char* m, ImVec4 c=OD::DIM){ snprintf(g_sc_status,sizeof(g_sc_status),"%s",m); g_sc_col=c; }

static std::string get_comm(pid_t pid){
    char path[64]; snprintf(path,sizeof(path),"/proc/%d/comm",pid);
    FILE* f=fopen(path,"r"); if(!f) return "";
    char buf[256]={}; fgets(buf,sizeof(buf),f); fclose(f);
    size_t n=strlen(buf); while(n>0&&(buf[n-1]=='\n'||buf[n-1]=='\r')) buf[--n]=0;
    return buf;
}

// ─────────────────────────────────────────────────────────────────────────────
// Memory read backends
// ─────────────────────────────────────────────────────────────────────────────
static bool read_vm_readv(pid_t pid, uintptr_t addr, void* out, size_t sz){
    iovec local={out,sz}, remote={(void*)addr,sz};
    return process_vm_readv(pid,&local,1,&remote,1,0)==(ssize_t)sz;
}
static bool read_proc_mem(pid_t pid, uintptr_t addr, void* out, size_t sz){
    char path[64]; snprintf(path,sizeof(path),"/proc/%d/mem",pid);
    int fd=open(path,O_RDONLY); if(fd<0) return false;
    bool ok=pread(fd,out,sz,(off_t)addr)==(ssize_t)sz;
    close(fd); return ok;
}
static bool read_ptrace_m(pid_t pid, uintptr_t addr, void* out, size_t sz){
    size_t done=0;
    while(done<sz){
        errno=0;
        long w=ptrace(PTRACE_PEEKDATA,pid,(void*)(addr+done),nullptr);
        if(errno) return false;
        size_t cp=std::min(sz-done,sizeof(long));
        memcpy((uint8_t*)out+done,&w,cp); done+=cp;
    }
    return true;
}
static bool mem_read(pid_t pid, uintptr_t addr, void* out, size_t sz){
    switch(g_method){
        case VM_READV: return read_vm_readv(pid,addr,out,sz);
        case PROC_MEM: return read_proc_mem(pid,addr,out,sz);
        case PTRACE_M: return read_ptrace_m(pid,addr,out,sz);
    }
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// Process helpers
// ─────────────────────────────────────────────────────────────────────────────
static void refresh_procs(){
    std::vector<ProcessEntry> tmp;
    DIR* d=opendir("/proc"); if(!d) return;
    dirent* de;
    while((de=readdir(d))){
        pid_t p=(pid_t)atoi(de->d_name); if(p<=0) continue;
        std::string name=get_comm(p); if(name.empty()) continue;
        tmp.push_back({p,name});
    }
    closedir(d);
    std::sort(tmp.begin(),tmp.end(),[](const ProcessEntry& a,const ProcessEntry& b){return a.pid<b.pid;});
    std::lock_guard<std::mutex> lk(g_procs_mtx);
    g_procs=std::move(tmp);
}

static void load_regions(pid_t pid){
    g_regions.clear();
    char path[64]; snprintf(path,sizeof(path),"/proc/%d/maps",pid);
    FILE* f=fopen(path,"r"); if(!f) return;
    char line[512];
    while(fgets(line,sizeof(line),f)){
        MemRegion r{}; char ignored[64]={};
        if(sscanf(line,"%lx-%lx %7s %63s %*s %*s %255[^\n]",
            &r.start,&r.end,r.perms,ignored,r.name)>=3)
            g_regions.push_back(r);
    }
    fclose(f);
}

static uintptr_t get_entry(pid_t pid){
    if(g_regions.empty()) return 0;
    return g_regions[0].start;
}

// ─────────────────────────────────────────────────────────────────────────────
// Attach / detach
// ─────────────────────────────────────────────────────────────────────────────
static bool try_attach(pid_t pid){
    if(g_method==PTRACE_M){
        if(ptrace(PTRACE_ATTACH,pid,nullptr,nullptr)<0){
            snprintf(g_attach_err,sizeof(g_attach_err),"BLOCKED — ptrace denied by kernel (PID %d)",pid);
            return false;
        }
        waitpid(pid,nullptr,0);
        ptrace(PTRACE_CONT,pid,nullptr,nullptr);
        return true;
    }
    load_regions(pid);
    uintptr_t test=0;
    for(auto& r:g_regions)
        if(r.perms[0]=='r'&&r.end-r.start>0){ test=r.start; break; }
    if(!test){
        snprintf(g_attach_err,sizeof(g_attach_err),"No readable region in PID %d",pid);
        return false;
    }
    uint8_t probe;
    if(!mem_read(pid,test,&probe,1)){
        snprintf(g_attach_err,sizeof(g_attach_err),
            "BLOCKED — %s denied by kernel (PID %d)",METHOD_NAMES[g_method],pid);
        return false;
    }
    g_hex_addr=test;
    snprintf(g_hex_input,sizeof(g_hex_input),"0x%lx",test);
    return true;
}

static void do_detach(){
    g_attached=false; g_pid=0; g_suspended=false;
    g_hex_live.store(false);
    g_hex_buf.clear(); g_regions.clear();
    g_results.clear(); g_first_scan=true;
    g_addrbook.clear();
    mv_status("Detached");
}

// ─────────────────────────────────────────────────────────────────────────────
// Background threads
// ─────────────────────────────────────────────────────────────────────────────
static void hex_thread_fn(){
    while(g_hex_live.load()){
        if(g_attached&&g_pid>0){
            constexpr size_t SZ=512;
            std::vector<uint8_t> buf(SZ,0);
            mem_read(g_pid,g_hex_addr,buf.data(),SZ);
            std::lock_guard<std::mutex> lk(g_hex_mtx);
            g_hex_buf=std::move(buf);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
}

static void scan_thread_fn(pid_t pid, int32_t val, bool first, int stype){
    g_scanning.store(true);
    sc_status("Scanning...",OD::YELLOW);

    char path[64]; snprintf(path,sizeof(path),"/proc/%d/maps",pid);
    FILE* f=fopen(path,"r"); if(!f){ g_scanning.store(false); return; }
    std::vector<std::pair<uintptr_t,uintptr_t>> regions;
    char line[512];
    while(fgets(line,sizeof(line),f)){
        uintptr_t s,e; char perms[8]={};
        if(sscanf(line,"%lx-%lx %7s",&s,&e,perms)==3)
            if(perms[0]=='r'&&e-s<32*1024*1024)
                regions.push_back({s,e});
    }
    fclose(f);

    std::vector<ScanResult> res;
    if(first){
        for(auto&[s,e]:regions){
            size_t sz=e-s;
            std::vector<uint8_t> buf(sz);
            if(!mem_read(pid,s,buf.data(),sz)) continue;
            for(size_t i=0;i+4<=sz;i+=4){
                int32_t v; memcpy(&v,buf.data()+i,4);
                if(v==val) res.push_back({s+i,v,v});
            }
        }
    } else {
        std::lock_guard<std::mutex> lk(g_results_mtx);
        for(auto& r:g_results){
            int32_t v=0;
            if(!mem_read(pid,r.address,&v,4)) continue;
            bool keep=false;
            switch(stype){
                case 0: keep=(v==val); break;
                case 1: keep=(v!=r.value); break;
                case 2: keep=(v==r.value); break;
                case 3: keep=(v>r.value); break;
                case 4: keep=(v<r.value); break;
            }
            if(keep) res.push_back({r.address,v,r.value});
        }
    }

    { std::lock_guard<std::mutex> lk(g_results_mtx); g_results=std::move(res); }
    char msg[64]; snprintf(msg,sizeof(msg),"Scan complete — %zu results",g_results.size());
    sc_status(msg,OD::GREEN);
    g_scanning.store(false);
}

// ─────────────────────────────────────────────────────────────────────────────
// ImGui style
// ─────────────────────────────────────────────────────────────────────────────
static void apply_style(){
    ImGuiStyle& s=ImGui::GetStyle();
    s.WindowRounding=4.f; s.FrameRounding=3.f;
    s.ScrollbarRounding=3.f; s.GrabRounding=3.f; s.TabRounding=3.f;
    s.WindowBorderSize=1.f; s.FrameBorderSize=0.f;
    s.ItemSpacing={6,4}; s.FramePadding={6,3};
    s.ScrollbarSize=12.f; s.WindowPadding={8,8};
    auto* c=s.Colors;
    c[ImGuiCol_WindowBg]             = OD::BG0;
    c[ImGuiCol_ChildBg]              = OD::BG1;
    c[ImGuiCol_PopupBg]              = OD::BG1;
    c[ImGuiCol_Border]               = OD::BORDER;
    c[ImGuiCol_FrameBg]              = OD::BG2;
    c[ImGuiCol_FrameBgHovered]       = {0.22f,0.25f,0.30f,1.f};
    c[ImGuiCol_FrameBgActive]        = {0.25f,0.28f,0.33f,1.f};
    c[ImGuiCol_TitleBg]              = OD::BG1;
    c[ImGuiCol_TitleBgActive]        = OD::BG2;
    c[ImGuiCol_TitleBgCollapsed]     = OD::BG0;
    c[ImGuiCol_MenuBarBg]            = OD::BG1;
    c[ImGuiCol_ScrollbarBg]          = OD::BG0;
    c[ImGuiCol_ScrollbarGrab]        = OD::BORDER;
    c[ImGuiCol_ScrollbarGrabHovered] = {0.30f,0.33f,0.38f,1.f};
    c[ImGuiCol_ScrollbarGrabActive]  = OD::BLUE;
    c[ImGuiCol_CheckMark]            = OD::BLUE;
    c[ImGuiCol_Button]               = OD::BG2;
    c[ImGuiCol_ButtonHovered]        = {0.25f,0.28f,0.34f,1.f};
    c[ImGuiCol_ButtonActive]         = OD::BLUE;
    c[ImGuiCol_Header]               = {0.20f,0.35f,0.55f,0.6f};
    c[ImGuiCol_HeaderHovered]        = {0.25f,0.40f,0.60f,0.8f};
    c[ImGuiCol_HeaderActive]         = OD::BLUE;
    c[ImGuiCol_Separator]            = OD::BORDER;
    c[ImGuiCol_Tab]                  = OD::BG1;
    c[ImGuiCol_TabHovered]           = OD::BG2;
    c[ImGuiCol_TabActive]            = OD::BG2;
    c[ImGuiCol_TabUnfocused]         = OD::BG0;
    c[ImGuiCol_TabUnfocusedActive]   = OD::BG1;
    c[ImGuiCol_Text]                 = OD::FG;
    c[ImGuiCol_TextDisabled]         = OD::DIM;
    c[ImGuiCol_TableHeaderBg]        = OD::BG2;
    c[ImGuiCol_TableBorderLight]     = OD::BORDER;
    c[ImGuiCol_TableBorderStrong]    = OD::BORDER;
    c[ImGuiCol_TableRowBg]           = {0,0,0,0};
    c[ImGuiCol_TableRowBgAlt]        = {1,1,1,0.03f};
}

// ─────────────────────────────────────────────────────────────────────────────
// Settings window
// ─────────────────────────────────────────────────────────────────────────────
static void draw_settings(){
    if(!g_show_settings) return;
    ImGui::SetNextWindowSize({520,320},ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowPos({400,220},ImGuiCond_FirstUseEver);
    if(!ImGui::Begin("Settings",&g_show_settings)){ ImGui::End(); return; }

    if(ImGui::BeginTabBar("##stabs")){
        if(ImGui::BeginTabItem("General")){
            static bool autoref=true, pause_on_attach=false;
            ImGui::Spacing();
            ImGui::Checkbox("Auto-refresh process list",&autoref);
            ImGui::Checkbox("Pause on attach",&pause_on_attach);
            ImGui::EndTabItem();
        }
        if(ImGui::BeginTabItem("Scan")){
            static int align=4;
            static bool writable=true,exec=false,cow=false;
            ImGui::Spacing();
            ImGui::Text("Default alignment:"); ImGui::SameLine();
            ImGui::SetNextItemWidth(60); ImGui::InputInt("##al",&align);
            ImGui::Checkbox("Writable",&writable);
            ImGui::SameLine(); ImGui::Checkbox("Executable",&exec);
            ImGui::SameLine(); ImGui::Checkbox("CopyOnWrite",&cow);
            ImGui::EndTabItem();
        }
        if(ImGui::BeginTabItem("Memory Read Method")){
            ImGui::Spacing();
            ImGui::TextColored(OD::FG,"Select how this tool reads process memory:");
            ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();

            ImGui::RadioButton("process_vm_readv",(int*)&g_settings_tmp,VM_READV);
            ImGui::SameLine(); ImGui::TextColored(OD::DIM,"— fast, blocked by KernelGuard patch");

            ImGui::RadioButton("/proc/PID/mem",(int*)&g_settings_tmp,PROC_MEM);
            ImGui::SameLine(); ImGui::TextColored(OD::DIM,"— slower, bypasses KernelGuard protection");

            ImGui::RadioButton("ptrace",(int*)&g_settings_tmp,PTRACE_M);
            ImGui::SameLine(); ImGui::TextColored(OD::DIM,"— traditional, blocked by KernelGuard");

            ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();

            // Warnings
            bool is_kg = g_pid>0 && get_comm(g_pid)=="kg_kernelguard";
            if((g_settings_tmp==VM_READV||g_settings_tmp==PTRACE_M) && is_kg)
                ImGui::TextColored(OD::RED,"  ⚠  This method is blocked by KernelGuard kernel patch");
            if(g_settings_tmp==PROC_MEM)
                ImGui::TextColored(OD::ORANGE,"  ⚠  This method bypasses kernel protection");

            ImGui::Spacing();
            float bw=80.f;
            ImGui::SetCursorPosX(ImGui::GetContentRegionAvail().x - bw*3 - 16.f);
            if(ImGui::Button("OK",{bw,0})){ g_method=g_settings_tmp; g_show_settings=false;
                mv_status(("Method: "+std::string(METHOD_NAMES[g_method])).c_str(),OD::CYAN); }
            ImGui::SameLine();
            if(ImGui::Button("Cancel",{bw,0})){ g_settings_tmp=g_method; g_show_settings=false; }
            ImGui::SameLine();
            if(ImGui::Button("Apply",{bw,0})){ g_method=g_settings_tmp;
                mv_status(("Method: "+std::string(METHOD_NAMES[g_method])).c_str(),OD::CYAN); }
            ImGui::EndTabItem();
        }
        if(ImGui::BeginTabItem("Hotkeys")){
            ImGui::Spacing();
            ImGui::Text("Ctrl+Q    Quit");
            ImGui::Text("Ctrl+S    Open Settings");
            ImGui::Text("F5        New Scan");
            ImGui::Text("F6        Next Scan");
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
    ImGui::End();
}

// ─────────────────────────────────────────────────────────────────────────────
// Memory Viewer window
// ─────────────────────────────────────────────────────────────────────────────
static bool g_quit = false;

static void draw_memory_viewer(){
    ImGui::SetNextWindowSize({920,640},ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowPos({20,30},ImGuiCond_FirstUseEver);

    if(!ImGui::Begin("Memory Viewer",nullptr,ImGuiWindowFlags_MenuBar)){ImGui::End();return;}

    // Menu bar
    if(ImGui::BeginMenuBar()){
        if(ImGui::BeginMenu("File")){
            if(ImGui::MenuItem("Settings","Ctrl+S")) g_show_settings=true;
            ImGui::Separator();
            if(ImGui::MenuItem("Exit","Ctrl+Q")) g_quit=true;
            ImGui::EndMenu();
        }
        if(ImGui::BeginMenu("Search")){ ImGui::MenuItem("Find address (TODO)"); ImGui::EndMenu(); }
        if(ImGui::BeginMenu("View")){
            if(ImGui::MenuItem("Refresh regions")) load_regions(g_pid);
            ImGui::EndMenu();
        }
        if(ImGui::BeginMenu("Debug")){ ImGui::MenuItem("Attach by PID"); ImGui::EndMenu(); }
        if(ImGui::BeginMenu("Tools")){ ImGui::MenuItem("Dump process (TODO)"); ImGui::EndMenu(); }
        if(ImGui::BeginMenu("Kernel tools")){ ImGui::MenuItem("dmesg log (TODO)"); ImGui::EndMenu(); }
        ImGui::SetCursorPosX(ImGui::GetContentRegionMax().x-22.f);
        if(ImGui::SmallButton("S")) g_show_settings=true;
        ImGui::EndMenuBar();
    }

    // Info bar
    ImGui::PushStyleColor(ImGuiCol_ChildBg,OD::BG2);
    ImGui::BeginChild("##info",{0,22},false);
    if(g_attached&&g_pid>0){
        uintptr_t base=g_regions.empty()?0:g_regions[0].start;
        uintptr_t bend=g_regions.empty()?0:g_regions.back().end;
        ImGui::TextColored(OD::DIM,"PID:"); ImGui::SameLine();
        ImGui::TextColored(OD::YELLOW,"%d",g_pid); ImGui::SameLine();
        ImGui::TextColored(OD::DIM,"  base:"); ImGui::SameLine();
        ImGui::TextColored(OD::BLUE,"0x%lx - 0x%lx",base,bend); ImGui::SameLine();
        ImGui::TextColored(OD::DIM,"  EntryPoint:"); ImGui::SameLine();
        ImGui::TextColored(OD::CYAN,"0x%lx",get_entry(g_pid)); ImGui::SameLine();
        ImGui::TextColored(OD::DIM,"  [%s]",get_comm(g_pid).c_str());
    } else {
        ImGui::TextColored(OD::DIM,"  No process attached");
    }
    ImGui::EndChild();
    ImGui::PopStyleColor();

    // Toolbar
    auto tbtn=[](const char* l)->bool{
        bool r=ImGui::Button(l); ImGui::SameLine(); return r;
    };
    ImGui::Spacing();
    if(tbtn("[Suspend]") && g_attached && !g_suspended){ kill(g_pid,SIGSTOP); g_suspended=true; mv_status("Suspended",OD::YELLOW); }
    if(tbtn("[Resume]")  && g_attached &&  g_suspended){ kill(g_pid,SIGCONT); g_suspended=false; mv_status("Resumed",OD::GREEN); }
    tbtn("[Debug]"); tbtn("[Dump Process]"); tbtn("[Symbols]"); tbtn("[Ring0_dump]");
    ImGui::NewLine(); ImGui::Separator();

    // Controls row
    ImGui::TextColored(OD::DIM,"Search"); ImGui::SameLine();
    ImGui::SetNextItemWidth(140); ImGui::InputText("##srch",g_scan_input,sizeof(g_scan_input));
    ImGui::SameLine(); ImGui::TextColored(OD::DIM,"type"); ImGui::SameLine();
    ImGui::SetNextItemWidth(80); ImGui::Combo("##vt",&g_value_type,VALUE_TYPES,6);
    ImGui::SameLine(); ImGui::TextColored(OD::DIM,"Memory Region"); ImGui::SameLine();
    ImGui::SetNextItemWidth(180);
    const char* cur_region = g_regions.empty() ? "(none)" : g_regions[std::min(g_region_sel,(int)g_regions.size()-1)].name;
    if(ImGui::BeginCombo("##reg",cur_region)){
        for(int i=0;i<(int)g_regions.size();i++){
            char lbl[128]; snprintf(lbl,sizeof(lbl),"0x%lx %s %s",g_regions[i].start,g_regions[i].perms,g_regions[i].name);
            if(ImGui::Selectable(lbl,g_region_sel==i)){
                g_region_sel=i; g_hex_addr=g_regions[i].start;
                snprintf(g_hex_input,sizeof(g_hex_input),"0x%lx",g_hex_addr);
            }
        }
        ImGui::EndCombo();
    }
    ImGui::SameLine(); ImGui::TextColored(OD::DIM,"Address to Read"); ImGui::SameLine();
    ImGui::SetNextItemWidth(150);
    if(ImGui::InputText("##ha",g_hex_input,sizeof(g_hex_input),ImGuiInputTextFlags_EnterReturnsTrue))
        sscanf(g_hex_input,"%lx",&g_hex_addr);
    ImGui::SameLine();
    if(!g_attached) ImGui::BeginDisabled();
    if(ImGui::Button("Go>>")) sscanf(g_hex_input,"%lx",&g_hex_addr);
    if(!g_attached) ImGui::EndDisabled();
    ImGui::Separator();

    // Main area
    float avail_h = ImGui::GetContentRegionAvail().y - 26.f;
    const float LIST_W = 195.f;

    // Process list
    ImGui::BeginChild("##pl",{LIST_W,avail_h},true);
    ImGui::TextColored(OD::DIM,"PROCESSES");
    ImGui::SameLine();
    if(ImGui::SmallButton("R##r")) g_procs_dirty.store(true);
    ImGui::SetNextItemWidth(-1);
    ImGui::InputTextWithHint("##pf","Filter...",g_proc_filter,sizeof(g_proc_filter));
    ImGui::BeginChild("##pl2",{0,0},false);
    {
        std::lock_guard<std::mutex> lk(g_procs_mtx);
        std::string flt(g_proc_filter);
        for(int i=0;i<(int)g_procs.size();i++){
            auto& p=g_procs[i];
            if(!flt.empty()&&p.name.find(flt)==std::string::npos&&
               std::to_string(p.pid).find(flt)==std::string::npos) continue;
            char lbl[80]; snprintf(lbl,sizeof(lbl),"%6d  %s",p.pid,p.name.c_str());
            ImVec4 col = (p.name=="kg_kernelguard")?OD::RED:
                         (p.name=="kg_normal"||p.name=="kg_memory")?OD::GREEN:OD::FG;
            ImGui::PushStyleColor(ImGuiCol_Text,col);
            if(ImGui::Selectable(lbl,g_proc_sel==i,ImGuiSelectableFlags_AllowDoubleClick)){
                g_proc_sel=i;
                snprintf(g_pid_input,sizeof(g_pid_input),"%d",p.pid);
                if(ImGui::IsMouseDoubleClicked(0)){
                    if(try_attach(p.pid)){
                        g_pid=p.pid; g_attached=true;
                        g_hex_live.store(true);
                        std::thread(hex_thread_fn).detach();
                        char msg[80]; snprintf(msg,sizeof(msg),"Attached %s (PID %d) via %s",
                            p.name.c_str(),p.pid,METHOD_NAMES[g_method]);
                        mv_status(msg,OD::GREEN);
                    } else mv_status(g_attach_err,OD::RED);
                }
            }
            ImGui::PopStyleColor();
        }
    }
    ImGui::EndChild();
    ImGui::EndChild();
    ImGui::SameLine();

    // Hex panel
    ImGui::BeginChild("##hp",{0,avail_h},false);

    // PID bar
    ImGui::TextColored(OD::DIM,"PID"); ImGui::SameLine();
    ImGui::SetNextItemWidth(70);
    ImGui::InputText("##pi",g_pid_input,sizeof(g_pid_input));
    ImGui::SameLine();
    if(g_attached) ImGui::BeginDisabled();
    if(ImGui::Button("Attach")){
        pid_t pid=(pid_t)atoi(g_pid_input);
        if(pid>0){
            if(try_attach(pid)){
                g_pid=pid; g_attached=true;
                g_hex_live.store(true);
                std::thread(hex_thread_fn).detach();
                char msg[80]; snprintf(msg,sizeof(msg),"Attached PID %d via %s",pid,METHOD_NAMES[g_method]);
                mv_status(msg,OD::GREEN);
            } else mv_status(g_attach_err,OD::RED);
        }
    }
    if(g_attached) ImGui::EndDisabled();
    ImGui::SameLine();
    if(!g_attached) ImGui::BeginDisabled();
    ImGui::PushStyleColor(ImGuiCol_Button,{0.35f,0.13f,0.14f,1.f});
    if(ImGui::Button("Detach")) do_detach();
    ImGui::PopStyleColor();
    if(!g_attached) ImGui::EndDisabled();
    ImGui::SameLine();
    if(g_attached){
        ImGui::TextColored(OD::GREEN,"● %s  [%s]",get_comm(g_pid).c_str(),METHOD_NAMES[g_method]);
    } else {
        ImGui::TextColored(OD::DIM,"○  not attached  [%s]",METHOD_NAMES[g_method]);
    }
    if(g_suspended){ ImGui::SameLine(); ImGui::TextColored(OD::YELLOW,"[SUSPENDED]"); }
    ImGui::Separator();

    // Hex dump
    ImGui::TextColored(OD::DIM,"Memory Viewer");
    ImGui::BeginChild("##hv",{0,0},true);

    std::vector<uint8_t> buf;
    { std::lock_guard<std::mutex> lk(g_hex_mtx); buf=g_hex_buf; }

    if(buf.empty()){
        ImGui::TextColored(OD::DIM, g_attached?"Reading memory...":"No process attached");
        ImGui::EndChild(); ImGui::EndChild();
        ImGui::Separator(); ImGui::TextColored(g_mv_col,"%s",g_mv_status);
        ImGui::End(); return;
    }

    constexpr int COLS=16;
    // column header
    ImGui::TextColored(OD::DIM,"  Address         ");
    for(int i=0;i<COLS;i++){ ImGui::SameLine(); ImGui::TextColored(OD::DIM,"%02X ",i); }
    ImGui::SameLine(); ImGui::TextColored(OD::DIM,"  ASCII");
    ImGui::SameLine(); ImGui::TextColored(OD::DIM,"   value");
    ImGui::Separator();

    int total=(int)(buf.size()/COLS);
    ImGuiListClipper clip; clip.Begin(total);
    while(clip.Step()){
        for(int row=clip.DisplayStart;row<clip.DisplayEnd;row++){
            size_t off=(size_t)row*COLS;
            ImGui::TextColored(OD::BLUE,"0x%014lx",g_hex_addr+off);
            for(int c=0;c<COLS;c++){
                if(off+c>=buf.size()) break;
                uint8_t b=buf[off+c];
                ImGui::SameLine();
                ImGui::TextColored(b==0?OD::DIM:OD::FG,"%02X ",b);
            }
            ImGui::SameLine(); ImGui::TextColored(OD::DIM,"  ");
            for(int c=0;c<COLS;c++){
                if(off+c>=buf.size()) break;
                uint8_t b=buf[off+c];
                char ch=(b>=0x20&&b<0x7f)?(char)b:'.';
                char s[2]={ch,0};
                ImGui::SameLine();
                ImGui::TextColored((b>=0x20&&b<0x7f)?OD::GREEN:OD::DIM,"%s",s);
            }
            if(off+4<=buf.size()){
                int32_t v; memcpy(&v,buf.data()+off,4);
                ImGui::SameLine(); ImGui::TextColored(OD::YELLOW,"  [%d]",v);
            }
        }
    }
    ImGui::EndChild();
    ImGui::EndChild();

    ImGui::Separator();
    ImGui::TextColored(g_mv_col,"%s",g_mv_status);
    ImGui::End();
}

// ─────────────────────────────────────────────────────────────────────────────
// KG Scanner window
// ─────────────────────────────────────────────────────────────────────────────
static void draw_scanner(){
    ImGui::SetNextWindowSize({680,580},ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowPos({960,30},ImGuiCond_FirstUseEver);
    if(!ImGui::Begin("KG Scanner")){ ImGui::End(); return; }

    // process label
    if(g_attached&&g_pid>0){
        char lbl[128]; snprintf(lbl,sizeof(lbl),"%08d-%s",g_pid,get_comm(g_pid).c_str());
        ImGui::TextColored(OD::CYAN,"%s",lbl);
    } else {
        ImGui::TextColored(OD::DIM,"(no process attached)");
    }
    ImGui::Separator();

    float avail  = ImGui::GetContentRegionAvail().y;
    float top_h  = avail*0.52f;
    float book_h = avail*0.32f;

    // Results + scan panel
    ImGui::BeginChild("##sa",{0,top_h},false);
    const float SP_W=205.f;

    // Results table
    ImGui::BeginChild("##rt",{-SP_W,0},true);
    ImGui::TextColored(OD::DIM,"Found:"); ImGui::SameLine();
    { std::lock_guard<std::mutex> lk(g_results_mtx); ImGui::TextColored(OD::GREEN,"%zu",g_results.size()); }
    ImGui::Separator();

    if(ImGui::BeginTable("##res",3,
        ImGuiTableFlags_Borders|ImGuiTableFlags_RowBg|
        ImGuiTableFlags_ScrollY|ImGuiTableFlags_SizingFixedFit)){
        ImGui::TableSetupScrollFreeze(0,1);
        ImGui::TableSetupColumn("Address",ImGuiTableColumnFlags_WidthFixed,130.f);
        ImGui::TableSetupColumn("V...",   ImGuiTableColumnFlags_WidthFixed,70.f);
        ImGui::TableSetupColumn("P...",   ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();
        std::lock_guard<std::mutex> lk(g_results_mtx);
        int show=(int)std::min(g_results.size(),(size_t)2000);
        ImGuiListClipper clip; clip.Begin(show);
        while(clip.Step()){
            for(int i=clip.DisplayStart;i<clip.DisplayEnd;i++){
                auto& r=g_results[i];
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0); ImGui::TextColored(OD::BLUE,"0x%lx",r.address);
                ImGui::TableSetColumnIndex(1); ImGui::TextColored(OD::GREEN,"%d",r.value);
                ImGui::TableSetColumnIndex(2); ImGui::TextColored(OD::DIM,"%d",r.prev_value);
                if(ImGui::IsItemHovered()&&ImGui::IsMouseDoubleClicked(0)){
                    AddrBookEntry e{}; e.address=r.address; e.value=r.value;
                    snprintf(e.desc,sizeof(e.desc),"No description");
                    g_addrbook.push_back(e);
                    g_hex_addr=r.address&~0xFULL;
                    snprintf(g_hex_input,sizeof(g_hex_input),"0x%lx",g_hex_addr);
                }
            }
        }
        ImGui::EndTable();
    }
    ImGui::EndChild();

    // Scan options panel
    ImGui::SameLine();
    ImGui::BeginChild("##sp",{SP_W,0},true);
    bool scanning=g_scanning.load();
    if(scanning||!g_attached) ImGui::BeginDisabled();
    if(ImGui::Button("New Scan",{-1,0})){
        int32_t v=atoi(g_scan_input); bool f=true;
        g_first_scan=false;
        std::thread([v,f]{ scan_thread_fn(g_pid,v,f,g_scan_type); }).detach();
    }
    if(ImGui::Button("Next Scan",{-1,0})){
        int32_t v=atoi(g_scan_input);
        std::thread([v]{ scan_thread_fn(g_pid,v,false,g_scan_type); }).detach();
    }
    if(scanning||!g_attached) ImGui::EndDisabled();
    if(ImGui::Button("Undo Scan",{-1,0})){
        std::lock_guard<std::mutex> lk(g_results_mtx);
        g_results.clear(); g_first_scan=true; sc_status("Scan reset",OD::DIM);
    }
    ImGui::Separator();
    ImGui::SetNextItemWidth(-1);
    ImGui::InputTextWithHint("##sv","Value...",g_scan_input,sizeof(g_scan_input));
    ImGui::Spacing();
    ImGui::TextColored(OD::DIM,"Scan Type");
    ImGui::SetNextItemWidth(-1); ImGui::Combo("##st",&g_scan_type,SCAN_TYPES,5);
    ImGui::Spacing();
    ImGui::TextColored(OD::DIM,"Value Type");
    ImGui::SetNextItemWidth(-1); ImGui::Combo("##vt2",&g_value_type,VALUE_TYPES,6);
    ImGui::Separator();
    ImGui::TextColored(OD::DIM,"Memory Scan Options");
    static bool cmp=false,wr=true,ex=false,cow=false,act=false,ld=false;
    ImGui::Checkbox("Compare to first scan",&cmp);
    ImGui::Checkbox("Writable",&wr); ImGui::SameLine(); ImGui::Checkbox("Executable",&ex);
    ImGui::Checkbox("CopyOnWrite",&cow);
    ImGui::Checkbox("Active memory only",&act);
    ImGui::Spacing();
    static int fa=4;
    ImGui::TextColored(OD::DIM,"Fast Scan"); ImGui::SameLine();
    ImGui::SetNextItemWidth(40); ImGui::InputInt("##fa",&fa,0);
    ImGui::Checkbox("Last Digits",&ld);
    ImGui::Separator();
    ImGui::TextColored(OD::DIM,"Method:"); ImGui::SameLine();
    ImGui::TextColored(g_method==PROC_MEM?OD::ORANGE:OD::RED,"%s",METHOD_NAMES[g_method]);
    if(ImGui::SmallButton("Change##m")) g_show_settings=true;
    ImGui::EndChild();

    ImGui::EndChild(); // scan area

    // Address Book
    ImGui::Separator();
    ImGui::TextColored(OD::DIM,"Address Book"); ImGui::SameLine();
    if(ImGui::SmallButton("+Add")){
        AddrBookEntry e{}; snprintf(e.desc,sizeof(e.desc),"No description");
        g_addrbook.push_back(e);
    }
    ImGui::BeginChild("##ab",{0,book_h},true);
    if(ImGui::BeginTable("##abt",6,
        ImGuiTableFlags_Borders|ImGuiTableFlags_RowBg|
        ImGuiTableFlags_SizingFixedFit|ImGuiTableFlags_ScrollY)){
        ImGui::TableSetupScrollFreeze(0,1);
        ImGui::TableSetupColumn("Active",     ImGuiTableColumnFlags_WidthFixed,45.f);
        ImGui::TableSetupColumn("Description",ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Address",    ImGuiTableColumnFlags_WidthFixed,130.f);
        ImGui::TableSetupColumn("Type",       ImGuiTableColumnFlags_WidthFixed,50.f);
        ImGui::TableSetupColumn("Value",      ImGuiTableColumnFlags_WidthFixed,65.f);
        ImGui::TableSetupColumn("Freeze",     ImGuiTableColumnFlags_WidthFixed,50.f);
        ImGui::TableHeadersRow();
        int del=-1;
        for(int i=0;i<(int)g_addrbook.size();i++){
            auto& e=g_addrbook[i];
            if(g_attached&&g_pid>0) mem_read(g_pid,e.address,&e.value,4);
            ImGui::TableNextRow();
            ImGui::PushID(i);
            ImGui::TableSetColumnIndex(0); ImGui::Checkbox("##cb",&e.frozen);
            ImGui::TableSetColumnIndex(1); ImGui::SetNextItemWidth(-1); ImGui::InputText("##d",e.desc,sizeof(e.desc));
            ImGui::TableSetColumnIndex(2);
            ImGui::TextColored(OD::BLUE,"0x%lx",e.address);
            if(ImGui::IsItemHovered()&&ImGui::IsMouseDoubleClicked(0)){
                g_hex_addr=e.address&~0xFULL;
                snprintf(g_hex_input,sizeof(g_hex_input),"0x%lx",g_hex_addr);
            }
            ImGui::TableSetColumnIndex(3); ImGui::TextColored(OD::PURPLE,"int32");
            ImGui::TableSetColumnIndex(4); ImGui::TextColored(OD::YELLOW,"%d",e.value);
            ImGui::TableSetColumnIndex(5); ImGui::TextColored(e.frozen?OD::RED:OD::DIM,e.frozen?"YES":"NO");
            if(ImGui::BeginPopupContextItem("##ctx")){
                if(ImGui::MenuItem("Remove")) del=i;
                ImGui::EndPopup();
            }
            ImGui::PopID();
        }
        if(del>=0) g_addrbook.erase(g_addrbook.begin()+del);
        ImGui::EndTable();
    }
    ImGui::EndChild();

    ImGui::Separator();
    ImGui::TextColored(g_sc_col,"%s",g_sc_status);
    ImGui::End();
}

// ─────────────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────────────
int main(){
    refresh_procs();

    SDL_Init(SDL_INIT_VIDEO);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION,3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION,3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK,SDL_GL_CONTEXT_PROFILE_CORE);

    SDL_Window* win=SDL_CreateWindow(
        "KG Debugger  |  KernelGuard Demo Tool",
        SDL_WINDOWPOS_CENTERED,SDL_WINDOWPOS_CENTERED,
        1680,740,
        SDL_WINDOW_OPENGL|SDL_WINDOW_SHOWN|SDL_WINDOW_RESIZABLE);
    SDL_GLContext ctx=SDL_GL_CreateContext(win);
    SDL_GL_MakeCurrent(win,ctx);
    SDL_GL_SetSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io=ImGui::GetIO();
    io.IniFilename=nullptr;
    // font removed
        

    apply_style();
    ImGui_ImplSDL2_InitForOpenGL(win,ctx);
    ImGui_ImplOpenGL3_Init("#version 330");

    bool running=true;
    while(running&&!g_quit){
        SDL_Event ev;
        while(SDL_PollEvent(&ev)){
            ImGui_ImplSDL2_ProcessEvent(&ev);
            if(ev.type==SDL_QUIT) running=false;
            if(ev.type==SDL_KEYDOWN){
                if(ev.key.keysym.sym==SDLK_q&&(SDL_GetModState()&KMOD_CTRL)) running=false;
                if(ev.key.keysym.sym==SDLK_s&&(SDL_GetModState()&KMOD_CTRL)) g_show_settings=true;
                if(ev.key.keysym.sym==SDLK_F5 && g_attached){
                    int32_t v=atoi(g_scan_input);
                    std::thread([v]{ scan_thread_fn(g_pid,v,true,g_scan_type); }).detach();
                }
                if(ev.key.keysym.sym==SDLK_F6 && g_attached){
                    int32_t v=atoi(g_scan_input);
                    std::thread([v]{ scan_thread_fn(g_pid,v,false,g_scan_type); }).detach();
                }
            }
        }

        if(g_procs_dirty.exchange(false))
            std::thread(refresh_procs).detach();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplSDL2_NewFrame();
        ImGui::NewFrame();

        draw_memory_viewer();
        draw_scanner();
        draw_settings();

        ImGui::Render();
        int W,H; SDL_GetWindowSize(win,&W,&H);
        glViewport(0,0,W,H);
        glClearColor(OD::BG0.x,OD::BG0.y,OD::BG0.z,1.f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        SDL_GL_SwapWindow(win);
    }

    g_hex_live.store(false);
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplSDL2_Shutdown();
    ImGui::DestroyContext();
    SDL_GL_DeleteContext(ctx);
    SDL_DestroyWindow(win);
    SDL_Quit();
    return 0;
}
