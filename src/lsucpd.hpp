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

void
sgj_hr_pri_helper(const std::string_view s, sgj_state * jsp);

/* sgj_hr_pri() is similar to sgj_pr_hr() [See sg_json.h]. The difference
 * is that this template function uses std::format() style formatting from
 * C++20 rather than C style as used in printf() . */
template<typename... Args>
constexpr void sgj_hr_pri(sgj_state * jsp, const std::string_view str_fmt,
                          Args&&... args)
{
    std::string s { BWP_FMTNS::vformat(str_fmt,
                                   BWP_FMTNS::make_format_args(args...)) };

    if ((NULL == jsp) || (! jsp->pr_as_json))
        fputs(s.c_str(), stdout);
    else if (jsp->pr_out_hr) {
        sgj_hr_pri_helper(s, jsp);
    }
}

// Assume this is initialized with '{ }' and is used with C functions like
// snprintf() and similar.
template <size_t N>
struct arr_of_ch {
    char d_[N];

    char & operator[](size_t k) { return d_[k]; }
    char operator[](size_t k) const { return d_[k]; }

    char at(size_t k) { if (k < N) return d_[k]; else return 0; }

    size_t size() const { return N; }
    size_t sz() const { return N; }

    char * begin() { return d_; }
    const char * begin() const { return d_; }
    char * data() { return d_; }
    const char * data() const { return d_; }
    char * d() { return d_; }
    const char * d() const { return d_; }

    char * end() { return d_ + N; }
    const char * end() const { return d_ + N; }

    size_t strlen() const {
	for (size_t k { }; k < N; ++k) {
	    if ('\0' == d_[k])
		return k;
	}
	return N;	// this flags there is an issue
    }
};
    

#endif          /* end of #ifndef LSUCPD_HPP */
