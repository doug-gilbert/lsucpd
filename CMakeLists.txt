cmake_minimum_required ( VERSION 3.5 )

project(lsucpd VERSION 0.91.9)
# Use version number: x.y.9 to indicate pre-release of x.(y+1) 
# Example: VERSION 0.91.9 is pre-release of 0.92

option ( BUILD_SHARED_LIBS "Build using shared libraries" ON)

set (CMAKE_CXX_STANDARD 20 )
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_CXX_EXTENSIONS OFF)

include ( CheckIncludeFile )
include ( CheckIncludeFileCXX )

CHECK_INCLUDE_FILE_CXX( "format" FORMAT_PRESENT )
CHECK_INCLUDE_FILE_CXX( "source_location" SOURCE_LOCATION_PRESENT )

if ( NOT FORMAT_PRESENT )
    add_definitions ( -lfmt )
endif ( NOT FORMAT_PRESENT )

if ( SOURCE_LOCATION_PRESENT )
    add_definitions ( -DHAVE_SOURCE_LOVATION )
endif ( SOURCE_LOCATION_PRESENT )

file ( GLOB sourcefiles "src/*.cpp" "src/*.c" ) 
file ( GLOB headerfiles "src/*.hpp" "src/*.h" ) 

add_executable (lsucpd ${sourcefiles} ${headerfiles} )

if ( BUILD_SHARED_LIBS )
    MESSAGE( ">> Build using shared libraries (default)" )
else ( BUILD_SHARED_LIBS )
    MESSAGE( ">> Trying to build a static executable" )
    add_definitions ( -static )
    target_link_libraries(lsucpd -static)
endif ( BUILD_SHARED_LIBS )

install(TARGETS lsucpd RUNTIME DESTINATION bin)

include(GNUInstallDirs)
file(ARCHIVE_CREATE OUTPUT lsucpd.8.gz PATHS doc/lsucpd.8 FORMAT raw COMPRESSION GZip)
install(FILES lsucpd.8.gz DESTINATION "${CMAKE_INSTALL_MANDIR}/man8")


set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
SET(CPACK_GENERATOR "DEB")
SET(CPACK_DEBIAN_PACKAGE_MAINTAINER "dpg") #required
include(CPack)
