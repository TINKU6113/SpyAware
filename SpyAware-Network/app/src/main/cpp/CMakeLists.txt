cmake_minimum_required(VERSION 3.22.1)
project("spyawarenative")

# Use zdtun's own build definition instead of hand-picking its source files.
# This already defines the "zdtun" target correctly for Android
# (zdtun.c + utils.c, -DANDROID, linked against liblog).
add_subdirectory(zdtun)

add_library(spyawarenative SHARED
    native-bridge.cpp
)

target_include_directories(spyawarenative PRIVATE zdtun)

find_library(log-lib log)

target_link_libraries(spyawarenative
    zdtun
    ${log-lib}
)