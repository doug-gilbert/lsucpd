/*
 * Copyright (c) 2022-2023 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>

#include "sg_pr2serr.h"

FILE * sg_warnings_strm = NULL;        /* would like to default to stderr */


int
pr2serr(const char * fmt, ...)
{
    va_list args;
    int n;

    va_start(args, fmt);
    n = vfprintf(stderr, fmt, args);
    va_end(args);
    return n;
}

int
pr2ws(const char * fmt, ...)
{
    va_list args;
    int n;

    va_start(args, fmt);
    n = vfprintf(sg_warnings_strm ? sg_warnings_strm : stderr, fmt, args);
    va_end(args);
    return n;
}

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
int
sg_scnpr(char * cp, int cp_max_len, const char * fmt, ...)
{
    va_list args;
    int n;

#ifdef DEBUG
    if (cp_max_len < 2) {
        /* stack backtrace would be good here ... */
        pr2ws("%s: buffer would overrun, 'fmt' string: %s\n", __func__, fmt);
        return 0;
    }
#else
    if (cp_max_len < 2)
        return 0;
#endif
    va_start(args, fmt);
    n = vsnprintf(cp, cp_max_len, fmt, args);
    va_end(args);
    return (n < cp_max_len) ? n : (cp_max_len - 1);
}

/* This function is similar to sg_scnpr() but takes the "n" in that pattern
 * as an extra, third argument where it is renamed 'off'. This function will
 * start writing chars at 'fcp + off' for no more than 'fcp_len - off - 1'
 * characters. The return value is the same as sg_scnpr(). */
int
sg_scn3pr(char * fcp, int fcp_len, int off, const char * fmt, ...)
{
    va_list args;
    const int cp_max_len = fcp_len - off;
    int n;

#ifdef DEBUG
    if (cp_max_len < 2) {
        /* stack backtrace would be good here ... */
        pr2ws("%s: buffer would overrun, 'fmt' string: %s\n", __func__, fmt);
        return 0;
    }
#else
    if (cp_max_len < 2)
        return 0;
#endif
    va_start(args, fmt);
    n = vsnprintf(fcp + off, fcp_len - off, fmt, args);
    va_end(args);
    return (n < cp_max_len) ? n : (cp_max_len - 1);
}
 

// Following borrowed from sg3_utils lib/sg_lib.c

/* If the number in 'buf' can not be decoded or the multiplier is unknown
 * then -1 is returned. Accepts a hex prefix (0x or 0X) or a decimal
 * multiplier suffix (as per GNU's dd (since 2002: SI and IEC 60027-2)).
 * Main (SI) multipliers supported: K, M, G. Ignore leading spaces and
 * tabs; accept comma, hyphen, space, tab and hash as terminator.
 * Handles zero and positive values up to 2**31-1 .
 * Experimental: left argument (must in with hexadecimal digit) added
 * to, or multiplied, by right argument. No embedded spaces.
 * Examples: '3+1k' (evaluates to 1027) and '0x34+1m'. */
int
sg_get_num(const char * buf)
{
    bool is_hex = false;
    int res, num, n, len;
    unsigned int unum;
    char * cp;
    const char * b;
    const char * b2p;
    char c = 'c';
    char c2 = '\0';     /* keep static checker happy */
    char c3 = '\0';     /* keep static checker happy */
    char lb[16];

    if ((NULL == buf) || ('\0' == buf[0]))
        return -1;
    len = strlen(buf);
    n = strspn(buf, " \t");
    if (n > 0) {
        if (n == len)
            return -1;
        buf += n;
        len -= n;
    }
    /* following hack to keep C++ happy */
    cp = strpbrk((char *)buf, " \t,#-");
    if (cp) {
        len = cp - buf;
        n = (int)sizeof(lb) - 1;
        len = (len < n) ? len : n;
        memcpy(lb, buf, len);
        lb[len] = '\0';
        b = lb;
    } else
        b = buf;

    b2p = b;
    if (('0' == b[0]) && (('x' == b[1]) || ('X' == b[1]))) {
        res = sscanf(b + 2, "%x%c", &unum, &c);
        num = unum;
        is_hex = true;
        b2p = b + 2;
    } else if ('H' == toupper((int)b[len - 1])) {
        res = sscanf(b, "%x", &unum);
        num = unum;
    } else
        res = sscanf(b, "%d%c%c%c", &num, &c, &c2, &c3);

    if (res < 1)
        return -1;
    else if (1 == res)
        return num;
    else {
        c = toupper((int)c);
        if (is_hex) {
            if (! ((c == '+') || (c == 'X')))
                return -1;
        }
        if (res > 2)
            c2 = toupper((int)c2);
        if (res > 3)
            c3 = toupper((int)c3);

        switch (c) {
        case 'C':
            return num;
        case 'W':
            return num * 2;
        case 'B':
            return num * 512;
        case 'K':
            if (2 == res)
                return num * 1024;
            if (('B' == c2) || ('D' == c2))
                return num * 1000;
            if (('I' == c2) && (4 == res) && ('B' == c3))
                return num * 1024;
            return -1;
        case 'M':
            if (2 == res)
                return num * 1048576;
            if (('B' == c2) || ('D' == c2))
                return num * 1000000;
            if (('I' == c2) && (4 == res) && ('B' == c3))
                return num * 1048576;
            return -1;
        case 'G':
            if (2 == res)
                return num * 1073741824;
            if (('B' == c2) || ('D' == c2))
                return num * 1000000000;
            if (('I' == c2) && (4 == res) && ('B' == c3))
                return num * 1073741824;
            return -1;
        case 'X':       /* experimental: multiplication */
            /* left argument must end with hexadecimal digit */
            cp = (char *)strchr(b2p, 'x');
            if (NULL == cp)
                cp = (char *)strchr(b2p, 'X');
            if (cp) {
                n = sg_get_num(cp + 1);
                if (-1 != n)
                    return num * n;
            }
            return -1;
        case '+':       /* experimental: addition */
            /* left argument must end with hexadecimal digit */
            cp = (char *)strchr(b2p, '+');
            if (cp) {
                n = sg_get_num(cp + 1);
                if (-1 != n)
                    return num + n;
            }
            return -1;
        default:
            pr2ws("unrecognized multiplier\n");
            return -1;
        }
    }
}

/* If the number in 'buf' can not be decoded then -1 is returned. Accepts a
 * hex prefix (0x or 0X) or a 'h' (or 'H') suffix; otherwise decimal is
 * assumed. Does not accept multipliers. Accept a comma (","), hyphen ("-"),
 * a whitespace or newline as terminator. */
int
sg_get_num_nomult(const char * buf)
{
    int res, len, num;
    unsigned int unum;
    char * commap;

    if ((NULL == buf) || ('\0' == buf[0]))
        return -1;
    len = strlen(buf);
    commap = (char *)strchr(buf + 1, ',');
    if (('0' == buf[0]) && (('x' == buf[1]) || ('X' == buf[1]))) {
        res = sscanf(buf + 2, "%x", &unum);
        num = unum;
    } else if (commap && ('H' == toupper((int)*(commap - 1)))) {
        res = sscanf(buf, "%x", &unum);
        num = unum;
    } else if ((NULL == commap) && ('H' == toupper((int)buf[len - 1]))) {
        res = sscanf(buf, "%x", &unum);
        num = unum;
    } else
        res = sscanf(buf, "%d", &num);
    if (1 == res)
        return num;
    else
        return -1;
}

/* If the number in 'buf' can not be decoded or the multiplier is unknown
 * then -1LL is returned. Accepts a hex prefix (0x or 0X), hex suffix
 * (h or H), or a decimal multiplier suffix (as per GNU's dd (since 2002:
 * SI and IEC 60027-2)).  Main (SI) multipliers supported: K, M, G, T, P
 * and E. Ignore leading spaces and tabs; accept comma, hyphen, space, tab
 * and hash as terminator. Handles zero and positive values up to 2**63-1 .
 * Experimental: left argument (must in with hexadecimal digit) added
 * to, or multiplied by right argument. No embedded spaces.
 * Examples: '3+1k' (evaluates to 1027) and '0x34+1m'. */
int64_t
sg_get_llnum(const char * buf)
{
    bool is_hex = false;
    int res, len, n;
    int64_t num, ll;
    uint64_t unum;
    char * cp;
    const char * b;
    const char * b2p;
    char c = 'c';
    char c2 = '\0';     /* keep static checker happy */
    char c3 = '\0';     /* keep static checker happy */
    char lb[32];

    if ((NULL == buf) || ('\0' == buf[0]))
        return -1LL;
    len = strlen(buf);
    n = strspn(buf, " \t");
    if (n > 0) {
        if (n == len)
            return -1LL;
        buf += n;
        len -= n;
    }
    /* following cast hack to keep C++ happy */
    cp = strpbrk((char *)buf, " \t,#-");
    if (cp) {
        len = cp - buf;
        n = (int)sizeof(lb) - 1;
        len = (len < n) ? len : n;
        memcpy(lb, buf, len);
        lb[len] = '\0';
        b = lb;
    } else
        b = buf;

    b2p = b;
    if (('0' == b[0]) && (('x' == b[1]) || ('X' == b[1]))) {
        res = sscanf(b + 2, "%" SCNx64 "%c", &unum, &c);
        num = unum;
        is_hex = true;
        b2p = b + 2;
    } else if ('H' == toupper((int)b[len - 1])) {
        res = sscanf(b, "%" SCNx64 , &unum);
        num = unum;
    } else
        res = sscanf(b, "%" SCNd64 "%c%c%c", &num, &c, &c2, &c3);

    if (res < 1)
        return -1LL;
    else if (1 == res)
        return num;
    else {
        c = toupper((int)c);
        if (is_hex) {
            if (! ((c == '+') || (c == 'X')))
                return -1;
        }
        if (res > 2)
            c2 = toupper((int)c2);
        if (res > 3)
            c3 = toupper((int)c3);

        switch (c) {
        case 'C':
            return num;
        case 'W':
            return num * 2;
        case 'B':
            return num * 512;
        case 'K':       /* kilo or kibi */
            if (2 == res)
                return num * 1024;
            if (('B' == c2) || ('D' == c2))
                return num * 1000;
            if (('I' == c2) && (4 == res) && ('B' == c3))
                return num * 1024;      /* KiB */
            return -1LL;
        case 'M':       /* mega or mebi */
            if (2 == res)
                return num * 1048576;   /* M */
            if (('B' == c2) || ('D' == c2))
                return num * 1000000;   /* MB */
            if (('I' == c2) && (4 == res) && ('B' == c3))
                return num * 1048576;   /* MiB */
            return -1LL;
        case 'G':       /* giga or gibi */
            if (2 == res)
                return num * 1073741824;        /* G */
            if (('B' == c2) || ('D' == c2))
                return num * 1000000000;        /* GB */
            if (('I' == c2) && (4 == res) && ('B' == c3))
                return num * 1073741824;        /* GiB */
            return -1LL;
        case 'T':       /* tera or tebi */
            if (2 == res)
                return num * 1099511627776LL;   /* T */
            if (('B' == c2) || ('D' == c2))
                return num * 1000000000000LL;   /* TB */
            if (('I' == c2) && (4 == res) && ('B' == c3))
                return num * 1099511627776LL;   /* TiB */
            return -1LL;
        case 'P':       /* peta or pebi */
            if (2 == res)
                return num * 1099511627776LL * 1024;
            if (('B' == c2) || ('D' == c2))
                return num * 1000000000000LL * 1000;
            if (('I' == c2) && (4 == res) && ('B' == c3))
                return num * 1099511627776LL * 1024;
            return -1LL;
        case 'E':       /* exa or exbi */
            if (2 == res)
                return num * 1099511627776LL * 1024 * 1024;
            if (('B' == c2) || ('D' == c2))
                return num * 1000000000000LL * 1000 * 1000;
            if (('I' == c2) && (4 == res) && ('B' == c3))
                return num * 1099511627776LL * 1024 * 1024;
            return -1LL;
        case 'X':       /* experimental: decimal (left arg) multiplication */
            cp = (char *)strchr(b2p, 'x');
            if (NULL == cp)
                cp = (char *)strchr(b2p, 'X');
            if (cp) {
                ll = sg_get_llnum(cp + 1);
                if (-1LL != ll)
                    return num * ll;
            }
            return -1LL;
        case '+':       /* experimental: decimal (left arg) addition */
            cp = (char *)strchr(b2p, '+');
            if (cp) {
                ll = sg_get_llnum(cp + 1);
                if (-1LL != ll)
                    return num + ll;
            }
            return -1LL;
        default:
            pr2ws("unrecognized multiplier\n");
            return -1LL;
        }
    }
}

/* If the number in 'buf' can not be decoded then -1 is returned. Accepts a
 * hex prefix (0x or 0X) or a 'h' (or 'H') suffix; otherwise decimal is
 * assumed. Does not accept multipliers. Accept a comma (","), hyphen ("-"),
 * a whitespace or newline as terminator. Only decimal numbers can represent
 * negative numbers and '-1' must be treated separately. */
int64_t
sg_get_llnum_nomult(const char * buf)
{
    int res, len;
    int64_t num;
    uint64_t unum;

    if ((NULL == buf) || ('\0' == buf[0]))
        return -1;
    len = strlen(buf);
    if (('0' == buf[0]) && (('x' == buf[1]) || ('X' == buf[1]))) {
        res = sscanf(buf + 2, "%" SCNx64 "", &unum);
        num = unum;
    } else if ('H' == toupper(buf[len - 1])) {
        res = sscanf(buf, "%" SCNx64 "", &unum);
        num = unum;
    } else
        res = sscanf(buf, "%" SCNd64 "", &num);
    return (1 == res) ? num : -1;
}

