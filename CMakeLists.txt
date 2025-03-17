cmake_minimum_required(VERSION 3.29)
project(MultiversionSigScanner)

set(CMAKE_CXX_STANDARD 26)

include(FetchContent)

# Optimize for speed
add_compile_options($<$<CONFIG:Release>:/O2>)
add_compile_options($<$<CONFIG:Release>:/Ot>)
add_compile_options($<$<CONFIG:Release>:/Ox>)
add_compile_options($<$<CONFIG:Release>:/Oy>)

# Enable intrinsic functions
add_compile_options($<$<CONFIG:Release>:/Oi>)

# Separate functions for the linker to improve the optimization process
add_compile_options($<$<CONFIG:Release>:/Gy>)

# Optimize global data to reduce the binary size
add_compile_options($<$<CONFIG:Release>:/Gw>)

# Enable string pooling to reduce binary size by consolidating duplicate strings
add_compile_options($<$<CONFIG:Release>:/GF>)

# Optimize floating point operations for speed (may introduce minor precision differences)
add_compile_options($<$<CONFIG:Release>:/fp:fast>)

# Disable RTTI (Run-Time Type Information) to reduce binary size and possibly improve performance
add_compile_options($<$<CONFIG:Release>:/GR->)

# Inline any suitable function to improve performance by reducing function call overhead
add_compile_options($<$<CONFIG:Release>:/Ob2>)

add_compile_definitions(_AMD64_)

FetchContent_Declare(
        libhat
        GIT_REPOSITORY  https://github.com/BasedInc/libhat.git
        GIT_TAG         7375873e560f46e8569c6a389c6077f4c7133089
)

FetchContent_Declare(
        json
        GIT_REPOSITORY https://github.com/nlohmann/json.git
        GIT_TAG v3.9.1
)

FetchContent_Declare(
        fmt
        GIT_REPOSITORY https://github.com/fmtlib/fmt.git
        GIT_TAG        master
)

FetchContent_MakeAvailable(libhat)
FetchContent_MakeAvailable(fmt)
FetchContent_MakeAvailable(json)

add_executable(MultiversionSigScanner main.cpp)
target_link_libraries(MultiversionSigScanner PRIVATE fmt::fmt libhat nlohmann_json Version.lib)
