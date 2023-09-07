#ifndef LSUCPD_HPP
#define LSUCPD_HPP

/*
 * Copyright (c) 2023 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <version>      // needed to define __cpp_lib_format (or not)

// [dpg] C++20 spec says '#define __cpp_lib_format 201907L so expect first
// [dpg] leg of following conditional will be chosen.
#ifdef __cpp_lib_format
    #include <format>
    #define BWP_FMT_LIB "std"
    #define BWP_FMTNS std
#else
    #include <fmt/core.h>
    #define BWP_FMT_LIB "libfmt"
    #define BWP_FMTNS fmt
#endif // __cpp_lib_format
// #include <format>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#include "sg_pr2serr.h"
#include "sg_json.h"

#ifdef HAVE_SOURCE_LOCATION
void
pr2ser(int vb_ge, const std::string & emsg,
       const std::error_code & ec = { },
       const std::source_location loc = std::source_location::current())
        noexcept;

void
pr3ser(int vb_ge, const std::string & e1msg,
       const char * e2msg = NULL,
       const std::error_code & ec = { },
       const std::source_location loc = std::source_location::current())
        noexcept;

void
pr4ser(int vb_ge, const std::string & e1msg,
       const std::string & e2msg, const char * e3msg = NULL,
       const std::error_code & ec = { },
       const std::source_location loc = std::source_location::current())
        noexcept;

#else

void
pr2ser(int vb_ge, const std::string & emsg,
       const std::error_code & ec = { }) noexcept;

void
pr3ser(int vb_ge, const std::string & e1msg,
       const char * e2msg = NULL,
       const std::error_code & ec = { }) noexcept;

void
pr4ser(int vb_ge, const std::string & e1msg,
       const std::string & e2msg, const char * e3msg = NULL,
       const std::error_code & ec = { }) noexcept;

#endif


extern int lsucpd_verbose;

template<typename... Args>
    constexpr void print_err(int vb_ge, const std::string_view str_fmt,
                             Args&&... args) noexcept {
        if (vb_ge >= lsucpd_verbose)       // vb_ge==-1 always prints
            return;
        fputs(BWP_FMTNS::vformat(str_fmt,
                                 BWP_FMTNS::make_format_args(args...)).c_str(),
                                 stderr);
}

template<typename... Args>
    constexpr std::string fmt_to_str(const std::string_view str_fmt,
                                     Args&&... args) noexcept {
        return BWP_FMTNS::vformat(str_fmt,
                                  BWP_FMTNS::make_format_args(args...));
}

#endif          /* end of #ifndef LSUCPD_HPP */
