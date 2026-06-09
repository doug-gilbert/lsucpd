#ifndef CONFIG_H
#define CONFIG_H

#cmakedefine HAVE_SOURCE_LOCATION 1
#cmakedefine FORMAT_PRESENT 1

#define BUILD_TIME "@BUILD_TIME@"

// #define SG_LIB_LINUX @OS_LINUX@
// #define SG_LIB_FREEBSD @OS_FREEBSD@
// #cmakedefine01 SG_LIB_AIX @SG_LIB_AIX@

// # This will generate a line in the output_file. Then in CMLists.txt:
// #      set(FEATURE_COMMENT "//")
// @FEATURE_COMMENT@#define OPTIONAL_SETTING 1

#endif
