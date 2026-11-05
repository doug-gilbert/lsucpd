#ifndef CONFIG_H
#define CONFIG_H

#cmakedefine HAVE_SOURCE_LOCATION 1
#cmakedefine FORMAT_PRESENT 1

#cmakedefine COMP_GCC 1
#cmakedefine COMP_CLANG 1
#cmakedefine COMP_MSVC 1
#cmakedefine COMP_UNKNOWN 1

#define BUILD_TIME "@BUILD_TIME@"

// # This will generate a line in the output_file. Then in CMLists.txt:
// #      set(FEATURE_COMMENT "//")
// @FEATURE_COMMENT@#define OPTIONAL_SETTING 1

#endif
