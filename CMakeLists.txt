cmake_minimum_required ( VERSION 3.10 )

project(lsucpd VERSION 0.91.9 LANGUAGES C CXX)
# Use version number: x.y.9 to indicate pre-release of x.(y+1) 
# Example: VERSION 0.91.9 is pre-release of 0.92

set ( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -g -Wall -W -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -DHAVE_CONFIG_H" )
set (CMAKE_CXX_STANDARD 20 )
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_CXX_EXTENSIONS OFF)
set ( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2 -g -Wall -W -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -DHAVE_CONFIG_H" )

string(TIMESTAMP BUILD_TIME "%Y%m%d %H:%M:%S")

option ( BUILD_SHARED_LIBS "Build using shared libraries" ON)
option ( ENABLE_DEBUG "Turn on debugging (extra warnings)" OFF)

include ( CheckIncludeFile )
include ( CheckIncludeFileCXX )
include ( GNUInstallDirs )

CHECK_INCLUDE_FILE_CXX( "format" FORMAT_PRESENT )
CHECK_INCLUDE_FILE_CXX( "source_location" SOURCE_LOCATION_PRESENT )

if ( NOT FORMAT_PRESENT )
    add_definitions ( -lfmt )
endif ( NOT FORMAT_PRESENT )

set (HAVE_SOURCE_LOCATION 0)
if ( SOURCE_LOCATION_PRESENT )
    set (HAVE_SOURCE_LOCATION 1)
endif ( SOURCE_LOCATION_PRESENT )

# Not much passed through config.h , perhaps more in the future
configure_file( ${CMAKE_SOURCE_DIR}/config.h.in.cmake ${CMAKE_BINARY_DIR}/config.h )


add_subdirectory( src )

add_subdirectory( doc )

install(FILES ChangeLog DESTINATION "${CMAKE_INSTALL_DOCDIR}")
install(FILES AUTHORS DESTINATION "${CMAKE_INSTALL_DOCDIR}")
install(FILES CREDITS DESTINATION "${CMAKE_INSTALL_DOCDIR}")
install(FILES README DESTINATION "${CMAKE_INSTALL_DOCDIR}")
install(FILES INSTALL DESTINATION "${CMAKE_INSTALL_DOCDIR}")


set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})

SET(CPACK_DEBIAN_PACKAGE_DESCRIPTION "List USB-C ports and Power Delivery (PD) interfaces")
SET(CPACK_DEBIAN_PACKAGE_MAINTAINER "Douglas Gilbert") 
SET(CPACK_DEBIAN_PACKAGE_SECTION "admin")
SET(CPACK_DEBIAN_PACKAGE_DEPENDS " ")

SET(CPACK_RPM_PACKAGE_DESCRIPTION "List USB-C ports and Power Delivery (PD) interfaces")
SET(CPACK_RPM_PACKAGE_LICENSE "BSD-2-clause")
SET(CPACK_RPM_PACKAGE_VENDOR "Douglas Gilbert")
SET(CPACK_RPM_PACKAGE_DEPENDS " ")

set(CPACK_GENERATOR "")
find_program(DPKG_EXECUTABLE dpkg)
if (DPKG_EXECUTABLE)
    list(APPEND CPACK_GENERATOR "DEB")
endif ()
find_program(RPMBUILD_EXECUTABLE rpmbuild)
if (RPMBUILD_EXECUTABLE)
    list(APPEND CPACK_GENERATOR "RPM")
endif ()

include(CPack)
include(CTest)
