bin_PROGRAMS = lsucpd

## .SUFFIXES: .cpp

# C++/clang testing
## CC = g++
## CC = clang++
## CXX = g++
## CXX = clang++

if DEBUG
# This is active if --enable-debug given to ./configure
DBG_CFLAGS = -Wextra -Wmisleading-indentation -Wduplicated-cond -Wlogical-op -Wnull-dereference -Wshadow -Wunused -Wsizeof-array-argument -Wduplicated-branches -Wjump-misses-init
DBG_CXXFLAGS = -DDEBUG -Wextra -Wmisleading-indentation -Wduplicated-cond -Wlogical-op -Wnull-dereference -Wshadow -Wunused -Wsizeof-array-argument -Wduplicated-branches
DBG_CXXCLANGFLAGS = -DDEBUG -Wextra -Wmisleading-indentation -Wnull-dereference -Wshadow -Wunused -Wsizeof-array-argument
DBG_CPPFLAGS = -DDEBUG
else
DBG_CFLAGS =
DBG_CXXFLAGS =
DBG_CPPFLAGS =
endif

# INCLUDES = -I$(top_srcdir)/include -I$(top_srcdir)/include/scsi

## AM_CPPFLAGS = -I$(top_srcdir)/src -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -Wall -W

# -std=<s> can be c99, c11, gnu11, etc.
###AM_CPPFLAGS = -iquote ${top_srcdir}/src -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 $(DBG_CPPFLAGS)
### AM_CFLAGS = -Wall -W $(DBG_CFLAGS)
# AM_CFLAGS = -Wall -W -fanalyzer $(DBG_CFLAGS)
# AM_CFLAGS = -Wall -W -pedantic -std=c++20 -fanalyzer $(DBG_CXXFLAGS)
# AM_CFLAGS = -Wall -W -pedantic -std=c++20 --analyze $(DBG_CXXFLAGS)
# AM_CFLAGS = -Wall -W -pedantic -std=c++23 $(DBG_CXXFLAGS)

# For g++ below
AM_CXXFLAGS = -Wall -W -pedantic -std=c++20 $(DBG_CXXFLAGS)
## AM_CXXFLAGS = -Wall -W -pedantic -std=c++20 -fanalyzer $(DBG_CXXFLAGS)
## AM_CXXFLAGS = -Wall -W -pedantic -std=c++23 $(DBG_CXXFLAGS)

# For clang++ below
## AM_CXXFLAGS = -Wall -W -pedantic -std=c++20 $(DBG_CXXCLANGFLAGS)
## AM_CXXFLAGS = -Wall -W -pedantic -std=c++20 --analyze $(DBG_CXXCLANGFLAGS)

lsucpd_SOURCES =	lsucpd.cpp \
			lsucpd.hpp \
			sg_json_builder.h \
			sg_json_builder.c \
			sgj_hr_pri_helper.cpp \
			sg_pr2serr.h \
			sg_pr2serr.c \
			sg_json.h \
			sg_json.c 

lsucpd_LDADD = @FMT_LDADD@

distclean-local:
	rm -rf .deps
