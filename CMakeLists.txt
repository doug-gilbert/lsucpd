cmake_minimum_required ( VERSION 3.10 )

project(lsucpd VERSION 0.91.9)
# Use version number: x.y.9 to indicate pre-release of x.(y+1) 
# Example: VERSION 0.91.9 is pre-release of 0.92

set ( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -g" )

option ( BUILD_SHARED_LIBS "Build using shared libraries" ON)
option ( ENABLE_DEBUG "Turn on debugging (extra warnings)" OFF)

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
    add_definitions ( -DHAVE_SOURCE_LOCATION )
endif ( SOURCE_LOCATION_PRESENT )

set ( sourcefiles
	src/lsucpd.cpp
	src/sgj_hr_pri_helper.cpp
	src/sg_json_builder.c
	src/sg_json.c
	src/sg_pr2serr.c
)

add_executable (lsucpd ${sourcefiles} )

target_compile_definitions(lsucpd PRIVATE _LARGEFILE64_SOURCE _FILE_OFFSET_BITS=64)
target_compile_options(lsucpd PRIVATE -Wall -W)
target_include_directories(lsucpd PRIVATE ${CMAKE_SOURCE_DIR}/src)

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
    target_link_libraries(lsucpd -static)
endif ( BUILD_SHARED_LIBS )

install(TARGETS lsucpd RUNTIME DESTINATION bin)

include(GNUInstallDirs)
file(ARCHIVE_CREATE OUTPUT lsucpd.8.gz PATHS doc/lsucpd.8 FORMAT raw COMPRESSION GZip)
file(ARCHIVE_CREATE OUTPUT lsucpd_json.8.gz PATHS doc/lsucpd_json.8 FORMAT raw COMPRESSION GZip)
install(FILES lsucpd.8.gz DESTINATION "${CMAKE_INSTALL_MANDIR}/man8")
install(FILES lsucpd_json.8.gz DESTINATION "${CMAKE_INSTALL_MANDIR}/man8")
install(FILES ChangeLog DESTINATION "${CMAKE_INSTALL_DOCDIR}")
install(FILES README DESTINATION "${CMAKE_INSTALL_DOCDIR}")
install(FILES INSTALL DESTINATION "${CMAKE_INSTALL_DOCDIR}")
install(FILES doc/usb_pd_pdo_rdo.pdf DESTINATION "${CMAKE_INSTALL_DOCDIR}")


set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
SET(CPACK_GENERATOR "DEB;RPM")
SET(CPACK_DEBIAN_PACKAGE_MAINTAINER "Douglas Gilbert") 
SET(CPACK_DEBIAN_PACKAGE_SECTION "admin")
SET(CPACK_RPM_PACKAGE_DESCRIPTION "List USB-C ports and Power Delivery (PD) interfaces")
SET(CPACK_RPM_PACKAGE_LICENSE "BSD-2-clause")
SET(CPACK_RPM_PACKAGE_VENDOR "Douglas Gilbert")

include(CPack)
include(CTest)
