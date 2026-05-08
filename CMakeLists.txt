cmake_minimum_required(VERSION 3.16)
project(KernelGuard LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Dependencies ──────────────────────────────────────────────────────────────
find_package(OpenGL REQUIRED)

# SDL2 — try cmake config first, fall back to pkg-config
find_package(SDL2 QUIET CONFIG)
if(NOT SDL2_FOUND)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(SDL2 REQUIRED sdl2)
endif()

# ── ImGui static library ──────────────────────────────────────────────────────
add_library(imgui_lib STATIC
    imgui/imgui.cpp
    imgui/imgui_draw.cpp
    imgui/imgui_tables.cpp
    imgui/imgui_widgets.cpp
    imgui/backends/imgui_impl_sdl2.cpp
    imgui/backends/imgui_impl_opengl3.cpp
)

target_include_directories(imgui_lib PUBLIC
    imgui/
    imgui/backends/
    ${SDL2_INCLUDE_DIRS}
)

# ── Helper to wire up a KernelGuard target ────────────────────────────────────
function(kg_target NAME SOURCE)
    add_executable(${NAME} ${SOURCE})
    target_include_directories(${NAME} PRIVATE
        imgui/
        imgui/backends/
        ${SDL2_INCLUDE_DIRS}
    )
    target_link_libraries(${NAME} PRIVATE
        imgui_lib
        ${SDL2_LIBRARIES}
        OpenGL::GL
        dl
        pthread
    )
endfunction()

# ── Targets ───────────────────────────────────────────────────────────────────
kg_target(kg_normal    programs/kg_normal.cpp)
kg_target(kg_memory    programs/kg_memory.cpp)
kg_target(kg_protected programs/kg_protected.cpp)
