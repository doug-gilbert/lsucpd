cmake_minimum_required (VERSION 3.0)

project(lsucpd VERSION 0.91.9)

set (CMAKE_CXX_STANDARD 20 )
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_CXX_EXTENSIONS OFF)

add_executable (lsucpd
	src/lsucpd.cpp
	src/sgj_hr_pri_helper.cpp
	src/sg_json_builder.c
	src/sg_json.c
	src/sg_pr2serr.c
)

MESSAGE( "CMAKE_INSTALL_PREFIX : ${CMAKE_INSTALL_PREFIX}" )

install(TARGETS lsucpd RUNTIME DESTINATION bin)

include(GNUInstallDirs)
file(ARCHIVE_CREATE OUTPUT lsucpd.8.gz PATHS doc/lsucpd.8 FORMAT raw COMPRESSION GZip)
install(FILES lsucpd.8.gz DESTINATION "${CMAKE_INSTALL_MANDIR}/man8")


set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
SET(CPACK_GENERATOR "DEB")
SET(CPACK_DEBIAN_PACKAGE_MAINTAINER "dpg") #required
include(CPack)
