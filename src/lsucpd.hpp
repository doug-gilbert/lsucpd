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

#include <format>

#include "sg_pr2serr.h"
#include "sg_json.h"

void
pr2ser(int vb_ge, const std::string & emsg,
       const std::error_code & ec = { },
       const std::source_location loc = std::source_location::current());

void
pr3ser(int vb_ge, const std::string & e1msg,
       const char * e2msg = NULL,
       const std::error_code & ec = { },
       const std::source_location loc = std::source_location::current());

void
pr4ser(int vb_ge, const std::string & e1msg,
       const std::string & e2msg, const char * e3msg = NULL,
       const std::error_code & ec = { },
       const std::source_location loc = std::source_location::current());


extern int lsucpd_verbose;

template<typename... Args> constexpr void print_err(int vb_ge, const std::string_view str_fmt, Args&&... args) {
	if (vb_ge >= lsucpd_verbose)       // vb_ge==-1 always prints
            return;
        fputs(std::vformat(str_fmt, std::make_format_args(args...)).c_str(), stderr);
}

template<typename... Args> constexpr std::string fmt_to_str(const std::string_view str_fmt, Args&&... args) {
        return std::vformat(str_fmt, std::make_format_args(args...));
}

#endif 		/* end of #ifndef LSUCPD_HPP */
