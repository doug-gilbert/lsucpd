
MESSAGE( STATUS ">> Entering src/CMakeLists.txt" )

set ( sourcefiles
	lsucpd.cpp
	sgj_hr_pri_helper.cpp
	sg_json_builder.c
	sg_json.c
	sg_pr2serr.c
)

add_executable (lsucpd ${sourcefiles} )

target_compile_definitions(lsucpd PRIVATE _LARGEFILE64_SOURCE _FILE_OFFSET_BITS=64)
target_compile_options(lsucpd PRIVATE -Wall -W)
target_include_directories(lsucpd PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_include_directories(lsucpd PRIVATE ${CMAKE_BINARY_DIR})

if ( ENABLE_DEBUG )
  target_compile_definitions(lsucpd PRIVATE DEBUG)
  target_compile_options(lsucpd PRIVATE
    -Wextra -Wmisleading-indentation -Wduplicated-cond -Wlogical-op
    -Wnull-dereference -Wshadow -Wunused -Wsizeof-array-argument
    -Wduplicated-branches -Wparentheses)
endif ( ENABLE_DEBUG )

if ( BUILD_SHARED_LIBS )
    MESSAGE( ">> Build using shared libraries (default)" )
else ( BUILD_SHARED_LIBS )
    MESSAGE( ">> Trying to build a static executable" )
    add_definitions ( -static )

    ## target_link_libraries(lsucpd -static)
    ## Wanted to build fully static executables but for g++ version 16 on
    ## Ubuntu 26.04 link fails saying in can't find libgcc_s_asneeded.so
    ## which is present (for gcc version 16) so it seems like a bug.
    ## If switch back to gcc-15 problem goes away. So ...
    ## Fully static C++ executables are very difficult in practice, go part way
    ## Also note that musl-gcc and clang do not have this problem.
    target_link_options(lsucpd PRIVATE
        -static-libstdc++
        -static-libgcc
    )
    target_link_libraries(lsucpd)

endif ( BUILD_SHARED_LIBS )

install(TARGETS lsucpd RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

