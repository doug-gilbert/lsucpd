#ifndef LSUPD_HPP
#define LSUPD_HPP

/*
 * Copyright (c) 2023 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "sg_pr2serr.h"
#include "sg_json.h"

void
pr2ser(const std::string & emsg, const std::error_code & ec = { },
       const std::source_location loc = std::source_location::current());

void
pr3ser(const std::string & e1msg, const char * e2msg = NULL,
       const std::error_code & ec = { },
       const std::source_location loc = std::source_location::current());

void
pr4ser(const std::string & e1msg, const std::string & e2msg,
       const char * e3msg = NULL, const std::error_code & ec = { },
       const std::source_location loc = std::source_location::current());


extern int lsupd_verbose;


#endif 		/* end of #ifndef LSUPD_HPP */
