#ifndef SG_PR2SERR_H
#define SG_PR2SERR_H

/*
 * Copyright (c) 2004-2023 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* pr2serr and pr2ws are convenience functions that replace the somewhat
 * long-winded fprintf(stderr, ....). The second form (i.e. pr2ws() ) is for
 * internal library use and may place its output somewhere other than stderr;
 * it depends on the external variable sg_warnings_strm which can be set
 * with sg_set_warnings_strm(). By default it uses stderr.
 * Note that this header and its implementation do not depend on sg_lib.[hc]
 * or any other sg3_utils components. */

#if __USE_MINGW_ANSI_STDIO -0 == 1
#define __printf(a, b) __attribute__((__format__(gnu_printf, a, b)))
#elif defined(__GNUC__) || defined(__clang__)
#define __printf(a, b) __attribute__((__format__(printf, a, b)))
#else
#define __printf(a, b)
#endif

int pr2serr(const char * fmt, ...) __printf(1, 2);

extern FILE * sg_warnings_strm;

/* Only difference between pr2serr() and pr2ws() is that the former always
 * send output to stderr. By default, pr2ws() also sends it output to
 * stderr. The sg_set_warnings_strm() function found in sg_lib.h (if used)
 * set another FILE * value. The functions in sg_lib.h send their error
 * output to pr2ws() . */
int pr2ws(const char * fmt, ...) __printf(1, 2);

/* Want safe, 'n += snprintf(b + n, blen - n, ...);' pattern that can
 * be called repeatedly. However snprintf() takes an unsigned second argument
 * (size_t) that explodes if 'blen - n' goes negative. This function instead
 * uses signed integers (second argument and return value) and is safe if the
 * second argument is negative. It returns number of chars actually
 * placed in cp excluding the trailing null char. So for cp_max_len > 0 the
 * return value is always < cp_max_len; for cp_max_len <= 1 the return value
 * is 0 and no chars are written to cp. Note this means that when
 * cp_max_len = 1, this function assumes that cp[0] is the null character
 * and does nothing (and returns 0). Linux kernel has a similar function
 * called  scnprintf().  */
int sg_scnpr(char * cp, int cp_max_len, const char * fmt, ...) __printf(3, 4);

/* This function is similar to sg_scnpr() but takes the "n" in that pattern
 * as an extra, third argument where it is renamed 'off'. This function will
 * start writing chars at 'fcp + off' for no more than 'fcp_len - off - 1'
 * characters. The return value is the same as sg_scnpr(). */
int sg_scn3pr(char * fcp, int fcp_len, int off,
              const char * fmt, ...) __printf(4, 5);

/* If the number in 'buf' can not be decoded or the multiplier is unknown
 * then -1 is returned. Accepts a hex prefix (0x or 0X) or a decimal
 * multiplier suffix (as per GNU's dd (since 2002: SI and IEC 60027-2)).
 * Main (SI) multipliers supported: K, M, G. Ignore leading spaces and
 * tabs; accept comma, hyphen, space, tab and hash as terminator.
 * Handles zero and positive values up to 2**31-1 .
 * Experimental: left argument (must in with hexadecimal digit) added
 * to, or multiplied, by right argument. No embedded spaces.
 * Examples: '3+1k' (evaluates to 1027) and '0x34+1m'. */
int sg_get_num(const char * buf);

/* If the number in 'buf' can not be decoded then -1 is returned. Accepts a
 * hex prefix (0x or 0X) or a 'h' (or 'H') suffix; otherwise decimal is
 * assumed. Does not accept multipliers. Accept a comma (","), hyphen ("-"),
 * a whitespace or newline as terminator. */
int sg_get_num_nomult(const char * buf);

/* If the number in 'buf' can not be decoded or the multiplier is unknown
 * then -1LL is returned. Accepts a hex prefix (0x or 0X), hex suffix
 * (h or H), or a decimal multiplier suffix (as per GNU's dd (since 2002:
 * SI and IEC 60027-2)).  Main (SI) multipliers supported: K, M, G, T, P
 * and E. Ignore leading spaces and tabs; accept comma, hyphen, space, tab
 * and hash as terminator. Handles zero and positive values up to 2**63-1 .
 * Experimental: left argument (must in with hexadecimal digit) added
 * to, or multiplied by right argument. No embedded spaces.
 * Examples: '3+1k' (evaluates to 1027) and '0x34+1m'. */
int64_t sg_get_llnum(const char * buf);

/* If the number in 'buf' can not be decoded then -1 is returned. Accepts a
 * hex prefix (0x or 0X) or a 'h' (or 'H') suffix; otherwise decimal is
 * assumed. Does not accept multipliers. Accept a comma (","), hyphen ("-"),
 * a whitespace or newline as terminator. Only decimal numbers can represent
 * negative numbers and '-1' must be treated separately. */
int64_t sg_get_llnum_nomult(const char * buf);

#ifdef __cplusplus
}
#endif

#endif
