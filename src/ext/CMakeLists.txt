file(GLOB_RECURSE H_FILES *.h)
file(GLOB_RECURSE C_FILES *.c)
file(GLOB_RECURSE HDR_FILES *.hpp)
file(GLOB_RECURSE SRC_FILES *.cpp)

add_library(ext ${H_FILES} ${C_FILES} ${HDR_FILES} ${SRC_FILES})

target_compile_options(ext PRIVATE -Wall -Wextra -pedantic -Wno-unused-parameter)
target_include_directories(ext PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# EccPoint_mult() trips a false positive in GCC's -Wmaybe-uninitialized. Silence it for that one
# file instead of the whole library, so the warning keeps working for everything else in here.
if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
    set_source_files_properties(${CMAKE_CURRENT_SOURCE_DIR}/micro-ecc/uECC.c
                                PROPERTIES COMPILE_OPTIONS -Wno-maybe-uninitialized)
endif ()
