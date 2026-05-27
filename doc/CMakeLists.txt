
MESSAGE( STATUS ">> Entering doc/CMakeLists.txt" )

file(ARCHIVE_CREATE OUTPUT ${CMAKE_BINARY_DIR}/doc/lsucpd.8.gz PATHS doc/lsucpd.8 FORMAT raw COMPRESSION GZip)
install(FILES ${CMAKE_BINARY_DIR}/doc/lsucpd.8.gz DESTINATION "${CMAKE_INSTALL_MANDIR}/man8")

file(ARCHIVE_CREATE OUTPUT ${CMAKE_BINARY_DIR}/doc/lsucpd_json.8.gz PATHS doc/lsucpd_json.8 FORMAT raw COMPRESSION GZip)
install(FILES ${CMAKE_BINARY_DIR}/doc/lsucpd_json.8.gz DESTINATION "${CMAKE_INSTALL_MANDIR}/man8")

install(FILES usb_pd_pdo_rdo.pdf DESTINATION "${CMAKE_INSTALL_DOCDIR}")

