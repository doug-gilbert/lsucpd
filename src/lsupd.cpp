/*
 * Copyright (c) 2023 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/* This is a utility program for listing USB Type C Power Delivery ports
 * and partners in Linux. It performs data-mining in the sysfs file
 * system assumed to be mounted under /sys . This utility does not require
 * root privileges.
 *
 */


// Initially this utility will assume C++20 or later

static const char * const version_str = "0.90 20230807 [svn: r5]";

static const char * const my_name { "lsupd: " };

#include <iostream>
#include <fstream>
#include <cstdint>
#include <filesystem>
#include <vector>
#include <map>
#include <ranges>
#include <algorithm>            // needed for ranges::sort()
#include <source_location>
#include <regex>
#include <cstring>              // needed for strstr()
#include <cstdio>               // using sscanf()
#include <getopt.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "lsupd.hpp"


/*
 * Some jargon:
 *    relative path: a path the does not start with '/'
 *    absolute path: a path that does start with '/'
 *    canonical path: an absolute path that contains no symlinks and
 *                    no specials (i.e. "." and "..")
 *    symlink: a symbolic link that often breaks the otherwise hierarchial
 *             nature of a file system, so they are evil
 *    symlink target: the destination of the symlink: a file, more often
 *                    a directory, may not even exist
 *    dangling or hanging symlink: one whose target does not exist
 *    link name of symlink: where the symlink actually resides, accessed
 *                          by the readlink(2) system call.
 *
 * Each file (including directories) has a unique canonical path. When a
 * directories's canonical path is required this utility uses the
 * following technique:
 *     1) change directory to the location [e.g. with if_directory_chdir() )
 *     2) if step 1) succeeds , call the getcwd(2) system call
 * If both steps succeed then we have the canonical path.
 *
 *
 * The USB PD protocol communicates over _one_ of the CC lines (therefore it
 * is half duplex) using "Biphase Mark Coding" (BMC). The now deprecated
 * USB PD revision 1 used "Binary Frequency Shift Keying" (BFSK) modulated
 * over the Vbus line. The term "SOP" (for Start Of Packet) appears often;
 * when used without a prime (quote symbol) it means the partner port;
 * when used with one prime (i.e. SOP') it means a chip in the cable
 * typically powered by Vconn; when used twice (i.e. SOP'') it means a
 * chip at the far end of the cable. USB PD is a multi-point protocol.
 */

namespace fs = std::filesystem;
using sstring=std::string;
using sregex=std::regex;
using strstr_m=std::map<sstring, sstring>;
// static auto & srgx_constants { std::regex_constants };
static auto & scout { std::cout };
static auto & scerr { std::cerr };

static const fs::directory_iterator end_itr { };
static const sstring empty_str { };
static const auto dir_opt = fs::directory_options::skip_permission_denied;

// vector of /sys/class/power_supply/ucsi* filename<
std::vector<sstring> pow_sup_ucsi_v;

int lsupd_verbose = 0;

enum class pw_op_mode_e {
    def = 0,    // "default": 5 Volts at 900 mA (need to confirm)
                // Is that 6 load_units ?
    v5i1_5,     // 5 Volts at "1.5A" (type C resistor setting)
    v5i3_0,     // 5 Volts at "3.0A" (type C resistor setting)
    usb_pd,     // "usb_power_delivery"
};

// This struct holds directory_entry_s of port<n>[-partner] objects found
// under the /sys/class/typec/ directory.
// Assume objects of this class can outlive *itr in the directory scan that
// was used to create them.
struct tc_dir_elem : public fs::directory_entry {
    tc_dir_elem(const fs::directory_entry & bs) : fs::directory_entry(bs) { };

    tc_dir_elem() : fs::directory_entry() { };

    // tc_dir_elem(const tc_dir_elem & ) = delete;

    bool is_partner() const { return partner_; }

    bool partner_ {false}; // mark non-static member variables with trailing _

    bool upd_dir_exists_ {false};

    bool source_sink_known_ {false};
    bool is_source_ { false };

    bool data_role_known_ {false};
    bool is_host_ { false };

    pw_op_mode_e pow_op_mode_ { pw_op_mode_e::def };

    unsigned int port_num_ {UINT32_MAX};    // if partner: local's port number

    int pd_inum_ {-1};

    int partner_ind_ { -1 }; // only >= 0 for local ports that have partners

    sstring match_str_;

    // maps /sys/class/typec/port<num>/* regular filenames to contents
    // only used for local ports
    std::map<sstring, sstring> tc_sdir_reg_m;
};

enum class pdo_e {
    pdo_null = 0,   // all 32 bits are zero, used a filler
    pdo_fixed,
    pdo_variable,
    pdo_battery,
    apdo_pps,   // SPR only: Vmin: 5 (was 3.3), Vmax: 21
                // in PPS the source does current limiting (CL)
    apdo_avs,   // EPR only: Vmin: 15; Vmax: 48
                // in AVS the source does NOT do current limiting (CL)
                // That is why the names are different: (SPR) PPS versus
                // (EPR) AVS
};

struct pdo_elem {
    enum pdo_e pdo_el_ { pdo_e::pdo_null };
    bool is_source_caps_;
    uint16_t pdo_ind_;
    uint32_t raw_pdo_;
    fs::path pdo_d_p_; // for example: /.../1:fixed_supply

    strstr_m ascii_pdo_m_;

    friend auto operator<=>(const pdo_elem & lhs, const pdo_elem & rhs)
        { return lhs.pdo_ind_ <=> rhs.pdo_ind_; }
    friend auto operator==(const pdo_elem & lhs, const pdo_elem & rhs)
        { return lhs.pdo_ind_ == rhs.pdo_ind_; }
};

// This struct holds directory_entry_s of pd<n> objects found under the
// the /sys/class/usb_power_delivery/ directory.
// Assume objects of this class can outlive *itr in the directory scan that
// created them.
struct upd_dir_elem : public fs::directory_entry {
    upd_dir_elem() = default;
    upd_dir_elem(const fs::directory_entry & bs) : fs::directory_entry(bs) { };

    sstring match_str_;

    std::vector<pdo_elem> source_pdo_v_;
    std::vector<pdo_elem> sink_pdo_v_;
};

// command line options and other things that would otherwise be at file
// scope. Don't mark with trailing _
struct opts_t {
    bool do_json;
    bool verbose_given;
    bool version_given;
    int do_caps;
    int do_help;
    int do_long;
    const char * pseudo_mount_point;
    const char * json_arg;  /* carries [JO] if any */
    const char * js_file; /* --js-file= argument */
    sgj_state json_st;  /* -j[JO] or --json[=JO] */
    // vector of sorted /sys/class/typec/*  tc_dir_elem objects
    std::vector<tc_dir_elem> tc_de_v;
    // map of <pd_num> to corresponding
    // /sys/class/usb_power_delivery/pd<pd_num> upd_dir_elem object
    std::map<int, upd_dir_elem> upd_de_m;
    // map of port_number to summary line string (with trailing \n)
    std::map<unsigned int, sstring> summ_out_m;

    std::vector<sstring> filter_port_v;
    std::vector<sstring> filter_pd_v;
};


// Note that "no_argument" entries should appear in chk_short_opts
static const struct option long_options[] = {
    {"cap", no_argument, 0, 'c'},
    {"caps", no_argument, 0, 'c'},
    {"capability", no_argument, 0, 'c'},
    {"capabilities", no_argument, 0, 'c'},
    {"help", no_argument, 0, 'h'},
    {"json", optional_argument, 0, '^'},    /* short option is '-j' */
    {"js-file", required_argument, 0, 'J'},
    {"js_file", required_argument, 0, 'J'},
    {"long", no_argument, 0, 'l'},
    {"sysfsroot", required_argument, 0, 'y'},
    {"verbose", no_argument, 0, 'v'},
    {"version", no_argument, 0, 'V'},
    {0, 0, 0, 0},
};

static sstring sysfs_root { "/sys" };
static const char * const upd_sn = "usb_power_delivery";
static const char * const class_s = "class";
static const char * const typec_s = "typec";
static const char * const powsup_sn = "power_supply";
static const char * const src_cap_s = "source-capabilities";
static const char * const sink_cap_s = "sink-capabilities";
static const char * const fixed_ln_sn = "fixed_supply";
static const char * const batt_ln_sn = "battery";
static const char * const vari_ln_sn = "variable_supply";
static const char * const pps_ln_sn = "programmable_supply";
static const char * const avs_ln_sn = "adjustable_supply";

static fs::path sc_pt;
static fs::path sc_typec_pt;
static fs::path sc_upd_pt;
static fs::path sc_powsup_pt;


static const char * const usage_message1 =
    "Usage: lsupd  [--caps] [--help] [--json[=JO]] [--js-file=JFN]\n"
    "              [--long] [--sysfsroot=SPATH] [--verbose] [--version]\n"
    "              [FILTER ...]\n"
    "  where:\n"
    "    --caps|-c         list pd sink and source capabilities\n"
    "    --help|-h         this usage information\n"
    "    --json[=JO]|-j[=JO]     output in JSON instead of plain text\n"
    "                            use --json=? for JSON help\n"
    "    --js-file=JFN|-J JFN    JFN is a filename to which JSON output is\n"
    "                            written (def: stdout); truncates then "
    "writes\n"
    "    --long|-l         supply more information\n"
    "    --sysfsroot=SPATH|-y SPATH    set sysfs mount point to SPATH (def: "
    "/sys)\n"
    "    --verbose|-v      increase verbosity, more debug information\n"
    "    --version|-V      output version string and exit\n\n";
static const char * const usage_message2 =
    "LiSt Usb-c Power Delivery (lsupd) information on the command line in a\n"
    "compact form. This utility obtains that information from sysfs (under:\n"
    "/sys ). FILTER arguments are optional; if present they are of the "
    "form:\n'p<num>[p]' or 'pd<num>'. The first is for matching (typec) "
    "ports and the\nsecond for matching pd objects. The first form may "
    "have a trailing 'p' for\nmatching its partner port. The FILTER "
    "arguments may be 'grep basic'\nregexes.\n";

static void
usage()
{
    scout << usage_message1;
    scout << usage_message2;
}

static sstring
pdo_e_to_str(enum pdo_e p_e)
{
    switch (p_e) {
    case pdo_e::pdo_fixed: return "fixed supply";
    case pdo_e::pdo_variable: return "variable supply";
    case pdo_e::pdo_battery: return "battery supply";
    case pdo_e::apdo_pps: return "programmable supply";
    case pdo_e::apdo_avs: return "adjustable supply";
    default: return "no supply";
    }
}

void
pr2ser(const std::string & emsg, const std::error_code & ec /* = { } */,
       const std::source_location loc /* = std::source_location::current() */)
{
    if (emsg.size() == 0) {     /* shouldn't need location.column() */
        if (lsupd_verbose > 1)
            scerr << loc.file_name() << " " << loc.function_name() << ";ln="
                  << loc.line() << "\n";
        else
            scerr << "pr2ser() called but no message?\n";
    } else if (ec) {
        if (lsupd_verbose > 1)
            scerr << loc.function_name() << ";ln=" << loc.line() << ": "
                  << emsg << ", error: " << ec.message() << "\n";
        else
            scerr << emsg << ", error: " << ec.message() << "\n";
    } else {
        if (lsupd_verbose > 1)
            scerr << loc.function_name() << ";ln=" << loc.line() <<  ": "
                  << emsg << "\n";
        else
            scerr << emsg << "\n";
    }
}

void
pr3ser(const std::string & e1msg, const char * e2msg /* = nullptr */,
       const std::error_code & ec,
       const std::source_location loc)
{
    if (e2msg == nullptr)
        pr2ser(e1msg, ec, loc);
    else if (ec) {
        if (lsupd_verbose > 1)
            scerr << loc.function_name() << ";ln=" << loc.line() << ": '"
                  << e1msg << "': " << e2msg << ", error: "
                  << ec.message() << "\n";
        else
            scerr << "'" << e1msg << "': " << e2msg << ", error: "
                  << ec.message() << "\n";
    } else {
        if (lsupd_verbose > 1)
            scerr << loc.function_name() << ";ln=" << loc.line() << ": '"
                  << e1msg << "': " << e2msg << "\n";
        else
            scerr << "'" << e1msg << "': " << e2msg << "\n";
    }
}

void
pr4ser(const std::string & e1msg, const std::string & e2msg,
       const char * e3msg /* = nullptr */, const std::error_code & ec,
       const std::source_location loc)
{
    if (e3msg == nullptr)
        pr3ser(e1msg, e2msg.c_str(), ec, loc);
    else if (ec) {
        if (lsupd_verbose > 1)
            scerr << loc.function_name() << ";ln=" << loc.line() << ": '"
                  << e1msg << "," << e2msg << "': " << e3msg
                  << ", error: " << ec.message() << "\n";
        else
            scerr << "'" << e1msg << "," << e2msg << "': " << e3msg
                  << ", error: " << ec.message() << "\n";
    } else {
        if (lsupd_verbose > 1)
            scerr << loc.function_name() << ";ln=" << loc.line() << ": '"
                  << e1msg << "," << e2msg << "': " << e3msg << "\n";
        else
            scerr << "'" << e1msg << "," << e2msg << "': " << e3msg << "\n";
    }
}

static void
regex_ctor_noexc(std::basic_regex<char> & pat, const sstring & filt,
                 std::regex_constants::syntax_option_type sot,
                 std::error_code & ec)
{
    ec.clear();

    try {
        sregex rx(filt, sot);

        rx.swap(pat);
    }
    catch (const std::regex_error & e) {
        scerr << e.what() << "\n";
        scerr << "CODE IS: " << e.code() << "\n";
        ec.assign(1, std::generic_category());
    }
    catch ( ... ) {
        scerr << "unknown exception\n";
        ec.assign(1, std::generic_category());
    }
}

// User can easily enter a regex pattern that causes std::regex_match() to
// throw. Catch everything and set an arbitrary error code.
static bool
regex_match_noexc(const sstring & actual, const std::basic_regex<char> & pat,
                  std::error_code & ec)
{
    bool res { false };

    ec.clear();
    try {
        res = std::regex_match(actual, pat);
    }
    catch (const std::regex_error & e) {
        scerr << e.what() << "\n";
        scerr << "CODE IS: " << e.code() << "\n";
        ec.assign(1, std::generic_category());
        res = false;
    }
    catch ( ... ) {
        scerr << "unknown exception\n";
        ec.assign(1, std::generic_category());
        res = false;
    }
    return res;
}

// If base_name.empty() is true, just use dir_or_fn_pt as name. If good
// and last char in val_out is '\n' then erase it.
// Returns errno in ec.value() if ec() is true, else returns false for good
static std::error_code
get_value(const fs::path & dir_or_fn_pt, const sstring & base_name,
          sstring & val_out, int max_value_len = 32)
{
    FILE * f;
    char * bp;
    fs::path vnm { base_name.empty() ? dir_or_fn_pt :
                                       dir_or_fn_pt / base_name };
    std::error_code ec { };

    val_out.clear();
    val_out.resize(max_value_len);
    bp = val_out.data();
    if (nullptr == (f = fopen(vnm.c_str(), "r"))) {
        ec.assign(errno, std::system_category());
        return ec;
    }
    if (nullptr == fgets(bp, max_value_len, f)) {
        /* assume empty */
        val_out.clear();
        fclose(f);
        return ec;
    }
    auto len = strlen(bp);
    if ((len > 0) && (bp[len - 1] == '\n')) {
        bp[len - 1] = '\0';
        --len;
    }
    // val_out = std::move( sstring { bp, len } );
    val_out.assign(bp, len);
    fclose(f);
    return ec;
}

/* If returned ec.value() is 0 (good return) then the directory dir_pt
 * has been scanned and all regular file names with the corresponding
 * contents form a pair inserted into map_io. Hidden files (files starting
 * with ".") are skipped. Only the first 32 bytes of each file are read. */
static std::error_code
map_d_regu_files(const fs::path & dir_pt, strstr_m & map_io,
              bool ignore_uevent = true)
{
    bool beyond_for = false;
    std::error_code ec { };

    for (fs::directory_iterator itr(dir_pt, dir_opt, ec);
         (! ec) && itr != end_itr;
         beyond_for = false, itr.increment(ec) ) {
        beyond_for = true;
        const fs::path & pt { itr->path() };
        const sstring & name { pt.filename() };
        sstring val;

        if (lsupd_verbose > 5)
            pr3ser(name, "filename() of entry in capabilities directory");
        if (fs::is_regular_file(*itr, ec) && (! pt.empty()) &&
            (pt.string()[0] != '.')) {
            if (ignore_uevent && (name == "uevent"))
                continue;
            ec = get_value(*itr, empty_str, val);
            if (ec)
                break;
            map_io[name] = val;
        } else if (ec)
            break;
    }
    if (ec && (! beyond_for))
        pr3ser(dir_pt, "was scanning when failed", ec);

    return ec;
}

// Expect to find keys: "power_role" and "power_operation_mode" in 'm'.
static bool
query_power_dir(const std::map<sstring, sstring> & m, bool & is_source,
                pw_op_mode_e & pom)
{
    bool res = false;
    const auto it { m.find("power_role") };

    if (it != m.end()) {
        if (strstr(it->second.c_str(), "[source]"))
            is_source = true;
        else if (strstr(it->second.c_str(), "[sink]"))
            is_source = false;
        else if (lsupd_verbose > 0) {
            is_source = false;
            pr3ser(it->second, "<< unexpected power_role");
        }
        res = true;
    } else
        is_source = false;

    const auto it2 = m.find("power_operation_mode");
    if (it2 != m.end()) {
        res = true;
        if (strstr(it2->second.c_str(), "default"))
            pom = pw_op_mode_e::def;
        else if (strstr(it2->second.c_str(), "1.5"))
            pom = pw_op_mode_e::v5i1_5;
        else if (strstr(it2->second.c_str(), "3.0"))
            pom = pw_op_mode_e::v5i3_0;
        else if (strstr(it2->second.c_str(), "power_delivery"))
            pom = pw_op_mode_e::usb_pd;
        else if (lsupd_verbose > 0) {
            pr3ser(it2->second, "<< unexpected power_operation_mode");
            pom = pw_op_mode_e::def;
        }
    } else
        pom = pw_op_mode_e::def;
    return res;
}

static bool
query_data_dir(const std::map<sstring, sstring> & m, bool & is_host)
{
    bool res = false;
    const auto it { m.find("data_role") };

    if (it != m.end()) {
        if (strstr(it->second.c_str(), "[host]"))
            is_host = true;
        else if (strstr(it->second.c_str(), "[device]"))
            is_host = false;
        else if (lsupd_verbose > 0) {
            is_host = false;
            pr3ser(it->second, "<< unexpected data_role");
        }
        res = true;
    } else
        is_host = false;
    return res;
}

static unsigned
get_millivolts(const sstring & name, const strstr_m & m)
{
    unsigned int mv;
    const strstr_m::const_iterator it = m.find(name);

    if (1 == sscanf(it->second.c_str(), "%umV", &mv))
        return mv;
    return 0;
}

static unsigned
get_milliamps(const sstring & name, const strstr_m & m)
{
    unsigned int ma;
    const strstr_m::const_iterator it = m.find(name);

    if (1 == sscanf(it->second.c_str(), "%umA", &ma))
        return ma;
    return 0;
}

static unsigned
get_milliwatts(const sstring & name, const strstr_m & m)
{
    unsigned int mw;
    const strstr_m::const_iterator it = m.find(name);

    if (1 == sscanf(it->second.c_str(), "%umW", &mw))
        return mw;
    return 0;
}

static unsigned
get_unitless(const sstring & name, const strstr_m & m)
{
    unsigned int mv;
    const strstr_m::const_iterator it = m.find(name);

    if (1 == sscanf(it->second.c_str(), "%u", &mv))
        return mv;
    return 0;
}

static void
build_raw_pdo(const fs::path & pt, pdo_elem & a_pdo)
{
    bool src_caps { a_pdo.is_source_caps_ };
    unsigned int mv, ma, mw;
    uint32_t r_pdo { };
    uint32_t v;
    std::error_code ec { map_d_regu_files(pt, a_pdo.ascii_pdo_m_) };

    if (ec) {
        pr3ser(pt, "failed in map_d_regu_files()", ec);
        a_pdo.raw_pdo_ = 0;
        return;
    }
    const auto & ss_map { a_pdo.ascii_pdo_m_ };

    if (ss_map.empty()) {
        a_pdo.raw_pdo_ = 0;
        return;
    }
    strstr_m::const_iterator it;
    const strstr_m::const_iterator it_end { };

    switch (a_pdo.pdo_el_) {
    case pdo_e::pdo_fixed:      // B31...B30: 00b
        mv = get_millivolts("voltage", ss_map);
        r_pdo = (mv / 50) & 0x3ff;
        ma = get_milliamps(src_caps ? "maximum_current" :
                                      "operational_current", ss_map);
        r_pdo |= ((ma / 10) & 0x3ff) << 10;
        if (a_pdo.pdo_ind_ == 1) {      // only pdo 1 set bits 23 to 29
            if (src_caps) {
                v = get_unitless("unchunked_extended_messages_supported",
                                 ss_map);
                if (v)
                    r_pdo |= 1 << 24;
            } else {
                v = get_unitless("fast_role_swap_current", ss_map);
                if (v)
                    r_pdo |= (v & 3) << 23;
            }
            v = get_unitless("dual_role_data", ss_map);
            if (v)
                r_pdo |= 1 << 25;
            v = get_unitless("usb_communication_capable", ss_map);
            if (v)
                r_pdo |= 1 << 26;
            v = get_unitless("unconstrained_power", ss_map);
            if (v)
                r_pdo |= (v & 1) << 27;
            if (src_caps) {
                v = get_unitless("usb_suspend_supported", ss_map);
                if (v)
                    r_pdo |= (v & 1) << 28;
            } else {
                v = get_unitless("higher_capability", ss_map);
                if (v)
                    r_pdo |= (v & 1) << 28;
            }
            v = get_unitless("dual_role_power", ss_map);
            if (v)
                r_pdo |= (v & 1) << 29;
        }
        break;
    case pdo_e::pdo_battery:    // B31...B30: 01b
        r_pdo = 1 << 30;
        mw = get_milliwatts(src_caps ? "maximum_allowable_power" :
                                       "operational_power", ss_map);
        r_pdo |= (mw / 250) & 0x3ff;
        mv = get_millivolts("minimum_voltage", ss_map);
        r_pdo |= ((mv / 50) & 0x3ff) << 10;
        mv = get_millivolts("maximum_voltage", ss_map);
        r_pdo |= ((mv / 50) & 0x3ff) << 20;
        break;
    case pdo_e::pdo_variable:   // B31...B30: 10b
        r_pdo = 1 << 31;
        ma = get_milliamps(src_caps ? "maximum_current" :
                                      "operational_current", ss_map);
        r_pdo |= (ma / 10) & 0x3ff;
        mv = get_millivolts("minimum_voltage", ss_map);
        r_pdo |= ((mv / 50) & 0x3ff) << 10;
        mv = get_millivolts("maximum_voltage", ss_map);
        r_pdo |= ((mv / 50) & 0x3ff) << 20;
        break;
    case pdo_e::apdo_pps:       // APDO: B31...B30: 11b; B29...B28: 00b [SPR]
        r_pdo = 3 << 30;
        ma = get_milliamps("maximum_current", ss_map);
        r_pdo |= (ma / 50) & 0x7f;
        mv = get_millivolts("minimum_voltage", ss_map);
        r_pdo |= ((mv / 100) & 0xff) << 8;
        mv = get_millivolts("maximum_voltage", ss_map);
        r_pdo |= ((mv / 100) & 0xff) << 17;
        if (src_caps) {
            v = get_unitless("pps_power_limited", ss_map);
            if (v)
                r_pdo |= (v & 1) << 27;
        }
        break;
    case pdo_e::apdo_avs:       // APDO: B31...B30: 11b; B29...B28: 01b [EPR]
        r_pdo = 3 << 30;
        r_pdo |= 1 << 28;
        mw = get_milliwatts("pdp", ss_map);
        r_pdo |= (mw / 1000) & 0xff;
        mv = get_millivolts("minimum_voltage", ss_map);
        r_pdo |= ((mv / 100) & 0xff) << 8;
        mv = get_millivolts("maximum_voltage", ss_map);
        r_pdo |= ((mv / 100) & 0x1ff) << 17;
        v = get_unitless("peak_current", ss_map);
        if (v)
            r_pdo |= (v & 3) << 26;
        break;
    default:
        r_pdo = 0;
        break;
    }
    a_pdo.raw_pdo_ = r_pdo;
}

static std::error_code
populate_pdos(const fs::path & cap_pt, bool is_source_caps,
              upd_dir_elem & val, struct opts_t * op)
{
    bool beyond_for = false;
    std::error_code ec { };
    std::vector<pdo_elem> pdo_el_v;

    for (fs::directory_iterator itr(cap_pt, dir_opt, ec);
         (! ec) && itr != end_itr;
         beyond_for = false, itr.increment(ec) ) {
        beyond_for = true;
        const fs::path & pt { *itr };
        sstring name { pt.filename() };

        if ((! name.empty()) && (isdigit(name[0]))) {
            int pdo_ind;
            const char * dp = name.data();

            if (1 == sscanf(dp, "%d", &pdo_ind)) {
                const char * cp = strchr(dp, ':');

                if (cp) {
                    pdo_elem a_pdo { };

                    a_pdo.pdo_ind_ = pdo_ind;
                    a_pdo.is_source_caps_ = is_source_caps;
                    if (0 == strcmp(cp + 1, fixed_ln_sn))
                        a_pdo.pdo_el_ = pdo_e::pdo_fixed;
                    else if (0 == strcmp(cp + 1, batt_ln_sn))
                        a_pdo.pdo_el_ = pdo_e::pdo_battery;
                    else if (0 == strcmp(cp + 1, vari_ln_sn))
                        a_pdo.pdo_el_ = pdo_e::pdo_variable;
                    else if (0 == strcmp(cp + 1, pps_ln_sn))
                        a_pdo.pdo_el_ = pdo_e::apdo_pps;
                    else if (0 == strcmp(cp + 1, avs_ln_sn))
                        a_pdo.pdo_el_ = pdo_e::apdo_avs;
                    else
                        a_pdo.pdo_el_ = pdo_e::pdo_null;

                    a_pdo.pdo_d_p_ = pt;
                    if (op->do_long > 0)
                        build_raw_pdo(pt, a_pdo);
                    pdo_el_v.push_back(a_pdo);
                }
            }
        }
    }
    if (ec && (! beyond_for))
        pr3ser(cap_pt, "was scanning when failed", ec);
    if (pdo_el_v.size() > 1)
        std::ranges::sort(pdo_el_v);

    if (is_source_caps)
        val.source_pdo_v_.swap(pdo_el_v);
    else
        val.sink_pdo_v_.swap(pdo_el_v);
    return ec;

}

static std::error_code
populate_src_snk_pdos(upd_dir_elem & val, struct opts_t * op)
{
    std::error_code ec { }, ec2 { };
    const fs::path & pd_pt { val.path() };

    const auto src_cap_pt = pd_pt / src_cap_s;
    if (fs::exists(src_cap_pt, ec)) {
        if (lsupd_verbose > 3)
            pr3ser(src_cap_pt, "exists");
        ec = populate_pdos(src_cap_pt, true, val, op);
    }
    const auto sink_cap_pt = pd_pt / sink_cap_s;
    if (fs::exists(sink_cap_pt, ec)) {
        if (lsupd_verbose > 3)
            pr3ser(sink_cap_pt, "exists");
        ec2 = populate_pdos(sink_cap_pt, false, val, op);
    }
    if (lsupd_verbose > 4)
        scerr << "Number of source PDOs: " << val.source_pdo_v_.size()
              << ", number of sink PDOs: " << val.sink_pdo_v_.size() << "\n";
    return ec ? ec : ec2;
}

static void
process_pw_dir_mode(const tc_dir_elem * elemp, bool is_partn, int clen,
                    char * c)
{
    const auto & pom = elemp->pow_op_mode_;
    static const char * dir_tail = "===";

    if (pom == pw_op_mode_e::usb_pd) {
        if (elemp->source_sink_known_) {
            if (is_partn) {
                if (elemp->is_source_)
                    snprintf(c, clen, " %s>> ", dir_tail);
                else
                    snprintf(c, clen, " <<%s ", dir_tail);
            } else {
                if (elemp->is_source_)
                    snprintf(c, clen, " > ");
                else
                    snprintf(c, clen, " < ");
            }
        } else if (is_partn)
            snprintf(c, clen, " %s ", dir_tail);
        else
            snprintf(c, clen, "  ");
    } else if (elemp->data_role_known_) {
        // in non-PD world: host implies source
        if (elemp->is_host_) {
            switch (pom) {
            case pw_op_mode_e::def:
                snprintf(c, clen, " > {5V, 0.9A}  ");
                break;
            case pw_op_mode_e::v5i1_5:
                snprintf(c, clen, " > {5V, 1.5A}  ");
                break;
            case pw_op_mode_e::v5i3_0:
                snprintf(c, clen, " > {5V, 3.0A}  ");
                break;
           default:
                if (lsupd_verbose > 0)
                    pr2serr("unexpected power_operation_mode "
                            "[%d]\n",
                            static_cast<int>(pom));
                snprintf(c, clen, " >     ");
                break;
            }
        } else
            snprintf(c, clen, " <     ");
    } else
        snprintf(c, clen, "   ");
}

static std::error_code
list_port(const tc_dir_elem & entry, struct opts_t * /* op */)
{
    std::error_code ec { };
    const fs::path & pt { entry.path() };
    sstring basename { pt.filename() };
    bool is_ptner = entry.is_partner();

    scout << (is_ptner ? "  " : "> ") << basename
          << "  [pd" << entry.pd_inum_ << "] :\n";
    if (entry.is_directory(ec) && entry.is_symlink(ec)) {
        if (! entry.is_partner()) {
            for (auto&& [n, v] : entry.tc_sdir_reg_m) {
                scout << "      " << n << "='" << v << "'\n";
            }
        }
    } else {
        if (ec)
            pr3ser(pt, "not symlink to directory", ec);
    }
    return ec;
}

static std::error_code
list_pd(int pd_num, const upd_dir_elem & upd_d_el,
        [[maybe_unused]] struct opts_t * op)
{
    std::error_code ec { };

    if (upd_d_el.source_pdo_v_.empty())
        scout << "> pd" << pd_num << ": has NO source_caps\n";
    else {
        scout << "> pd" << pd_num << ": source capabilities:\n";
        for (const auto& a_pdo : upd_d_el.source_pdo_v_) {

            scout << "  >>> " << a_pdo.pdo_d_p_.filename()
                  << ", type: " << pdo_e_to_str(a_pdo.pdo_el_) << "\n";
            if (a_pdo.ascii_pdo_m_.empty()) {
                strstr_m  map_io;

                ec = map_d_regu_files(a_pdo.pdo_d_p_, map_io);
                if (ec) {
                    pr3ser(a_pdo.pdo_d_p_, "failed in map_d_regu_files()",
                           ec);
                    break;
                }
                for (auto&& [n, v] : map_io)
                    scout << "      " << n << "='" << v << "'\n";
            } else {
                for (auto&& [n, v] : a_pdo.ascii_pdo_m_)
                    scout << "      " << n << "='" << v << "'\n";
            }
            if (op->do_long > 0)
                scout << "        raw_pdo: 0x" << std::hex << a_pdo.raw_pdo_
                      << "\n";
        }
    }
    if (ec)
        return ec;

    if (upd_d_el.sink_pdo_v_.empty())
        scout << "> pd" << pd_num << ": has NO sink_caps\n";
    else {
        scout << "> pd" << pd_num << ": sink capabilities:\n";
        for (const auto& a_pdo : upd_d_el.sink_pdo_v_) {
            scout << "  >>> " << a_pdo.pdo_d_p_.filename()
                  << ", type: " << pdo_e_to_str(a_pdo.pdo_el_) << "\n";
            if (a_pdo.ascii_pdo_m_.empty()) {
                strstr_m  map_io;

                ec = map_d_regu_files(a_pdo.pdo_d_p_, map_io);
                if (ec) {
                    pr3ser(a_pdo.pdo_d_p_, "failed in map_d_regu_files()", ec);
                    break;
                }
                for (auto&& [n, v] : map_io)
                    scout << "      " << n << "='" << v << "'\n";
            } else {
                for (auto&& [n, v] : a_pdo.ascii_pdo_m_)
                    scout << "      " << n << "='" << v << "'\n";
            }
            if (op->do_long > 0)
                scout << "        raw_pdo: 0x" << std::hex << a_pdo.raw_pdo_
                      << "\n";
        }
    }
    return ec;
}

/* Handles short options after '-j' including a sequence of short options
 * that include one 'j' (for JSON). Want optional argument to '-j' to be
 * prefixed by '='. Return 0 for good, 1 for syntax error
 * and 2 for exit with no error. */
static int
chk_short_opts(const char sopt_ch, struct opts_t * op)
{
    /* only need to process short, non-argument options */
    switch (sopt_ch) {
    case 'c':
        op->do_caps = true;
        break;
    case 'h':
    case '?':
        ++op->do_help;
        break;
    case 'j':
        break;  /* simply ignore second 'j' (e.g. '-jxj') */
    case 'l':
        ++op->do_long;
        break;
    case 'v':
        op->verbose_given = true;
        ++lsupd_verbose;
        break;
    case 'V':
        op->version_given = true;
        break;
    default:
        pr2serr("unrecognised option code %c [0x%x] ??\n", sopt_ch, sopt_ch);
        return 1;
    }
    return 0;
}


int
main(int argc, char * argv[])
{
    bool filter_for_port { false };
    bool filter_for_pd { false };
    bool beyond_for { false };
    bool ucsi_psup_possible { false };
    std::error_code ec { };
    struct opts_t opts { };
    struct opts_t * op = &opts;
    sgj_state * jsp;
    sgj_opaque_p jop = nullptr;
    tc_dir_elem * elemp;
    int res { };
    size_t sz;
    char b[128];
    static const int blen = sizeof(b);

    while (1) {
        int option_index = 0;

        int c = getopt_long(argc, argv, "^chj::J:lvVy:", long_options,
                            &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'c':
            op->do_caps = true;
            break;
        case 'h':
            ++op->do_help;
            break;
        case 'j':       /* for: -j[=JO] */
        case '^':       /* for: --json[=JO] */
            op->do_json = true;
            /* Now want '=' to precede all JSON optional arguments */
            if (optarg) {
                int k, n, q;

                if ('^' == c) {
                    op->json_arg = optarg;
                    break;
                } else if ('=' == *optarg) {
                    op->json_arg = optarg + 1;
                    break;
                }
                n = strlen(optarg);
                for (k = 0; k < n; ++k) {
                    q = chk_short_opts(*(optarg + k), op);
                    if (1 == q)
                        return 1;
                    if (2 == q)
                        return 0;
                }
            } else
                op->json_arg = nullptr;
            break;
       case 'J':
            op->do_json = true;
            op->js_file = optarg;
            break;
        case 'l':
            ++op->do_long;
            break;
        case 'v':
            op->verbose_given = true;
            ++lsupd_verbose;
            break;
        case 'V':
            op->version_given = true;
            break;
        case 'y':
            op->pseudo_mount_point = optarg;
            break;
        default:
            scerr << "unrecognised option code 0x" << c << "\n";
            usage();
            return 1;
        }
    }
    while (optind < argc) {
        const char * oip = argv[optind];

        if (tolower(oip[0]) != 'p') {
            scerr << "FILTER arguments must start with a 'p'\n\n";
            usage();
            return 1;
        }
        if (tolower(oip[1]) == 'd')
            op->filter_pd_v.push_back(oip);
        else {
            auto ln = strlen(oip);
            char b[32] { };

            if ((ln < 2) || (ln >= 31)) {
                scerr << "expect port matching argument of the form "
                         "'p<num>[p]'\n";
                return 1;
            }
            strncpy(b, oip, ln);
            if (b[ln - 1] == 'P')
                b[ln - 1] = 'p';
            op->filter_port_v.push_back(b);
        }
        ++optind;
    }
    if (op->do_help > 0) {
        usage();
        return 0;
    }
    if (op->version_given) {
        scout << version_str << "\n";
        return 0;
    }
    if (op->filter_port_v.size() > 0)
        filter_for_port = true;
    if (op->filter_pd_v.size() > 0) {
        filter_for_pd = true;
        op->do_caps = true;     // pd<n> holds caps
    }
    if (filter_for_port && filter_for_pd) {
        scerr << "can filter for ports or pd objects, but not both\n\n";
        usage();
        return 1;
    }

    jsp = &op->json_st;
    if (op->do_json) {
       if (! sgj_init_state(jsp, op->json_arg)) {
            int bad_char = jsp->first_bad_char;
            char e[1500];

            if (bad_char) {
                pr2serr("bad argument to --json= option, unrecognized "
                        "character '%c'\n\n", bad_char);
            }
            sg_json_usage(0, e, sizeof(e));
            pr2serr("%s", e);
            res = 1;
            goto fini;
        }
        jop = sgj_start_r(my_name, version_str, argc, argv, jsp);
        sgj_js_nv_s(jsp, jop, "utility_state", "under development");
    }
    if (op->pseudo_mount_point) {
        const fs::path & pt { op->pseudo_mount_point };

        if (! fs::exists(pt, ec)) {
            if (ec) {
                pr3ser(pt, "fs::exists error", ec);
            } else
                pr3ser(pt, "does not exist");
            return 1;
        } else if (! fs::is_directory(pt, ec)) {
            if (ec) {
                pr3ser(pt, "fs::is_directory error", ec);
            } else
                pr3ser(pt, "is not a directory");
            return 1;
        } else
            sysfs_root = pt;
    }
    sc_pt = fs::path(sysfs_root) / class_s;
    sc_typec_pt = sc_pt / typec_s;
    sc_upd_pt = sc_pt / upd_sn;
    sc_powsup_pt = sc_pt / powsup_sn;

    // choose traditional for loop over range-based for, for flexibility
    for (fs::directory_iterator itr(sc_typec_pt, dir_opt, ec);
         (! ec) && itr != end_itr;
         beyond_for = false, itr.increment(ec) ) {
        beyond_for = true;
        const fs::path & it_pt { itr->path() };
        const sstring basename = it_pt.filename();

        if (lsupd_verbose > 4)
            pr3ser(basename, "filename() of entry in /sys/class/typec");
        const char * base_s = basename.data();
        tc_dir_elem de { *itr };

        if (itr->is_directory(ec) && itr->is_symlink(ec)) {

            if (1 != sscanf(base_s, "port%u", &de.port_num_)) {
                if (lsupd_verbose > 0)
                    pr3ser(it_pt, "unable to decode 'port<num>', skip");
                continue;
            } else {
                de.match_str_ = sstring("p") + std::to_string(de.port_num_);
                if (strstr(base_s, "partner")) {
                    // needs C++23: if (basename.contains("partner"))
                    de.partner_ = true;
                    de.match_str_ += "p";
                } else {
                    ec = map_d_regu_files(it_pt, de.tc_sdir_reg_m);
                    if (ec) {
                        pr3ser(it_pt, "failed in map_d_regu_files()", ec);
                        break;
                    }
                    de.source_sink_known_ = query_power_dir(de.tc_sdir_reg_m,
                                                            de.is_source_,
                                                            de.pow_op_mode_);
                    de.data_role_known_ = query_data_dir(de.tc_sdir_reg_m,
                                                         de.is_host_);
                }
            }
            fs::path pt { it_pt / upd_sn };

            if (fs::exists(pt, ec)) {
                sstring attr;
                int k;

                de.upd_dir_exists_ = true;
                fs::path c_pt { fs::canonical(pt, ec) };
                if (ec) {
                    pr3ser(pt, "failed to canonize", ec);
                    break;
                }
                sstring pd_x { c_pt.filename() };
                if (1 != sscanf(pd_x.c_str(), "pd%d", &k)) {
                    pr3ser(pd_x, "sscanf could find match");
                } else
                    de.pd_inum_ = k;
                if (de.partner_)
                    ucsi_psup_possible = true;
                else {
                    ec = get_value(itr->path(), "power_role", attr);
                    if (ec) {
                        pr3ser(itr->path(), "returned by get_value()", ec);
                    } else {
                        if (lsupd_verbose > 3)
                            scerr << "power_role: " << attr << "\n";
                    }
                }
            }
        } else {
            if (ec) {
                pr3ser(itr->path(), "not symlink to directory", ec);
                break;
            }
        }
        op->tc_de_v.push_back(de);
    }
    if (ec) {
        if (! beyond_for)
            pr3ser(sc_typec_pt, "failed in iterate of scan directory", ec);
        return 1;
    }
    sz = op->tc_de_v.size();
    if (sz > 1) {
        std::ranges::sort(op->tc_de_v);
        // assume, for example, "port3" precedes "port3-partner" after sort

        tc_dir_elem * prev_elemp = nullptr;
        int b_ind { };
        char c[32];
        static const int clen = sizeof(c);

        if (ucsi_psup_possible) {
            for (fs::directory_iterator itr(sc_powsup_pt, dir_opt, ec);
                 (! ec) && itr != end_itr;
                 beyond_for = false, itr.increment(ec) ) {
                const fs::path & pt { itr->path() };
                const sstring & name { pt.filename() };

// xxxxxxxxxxx
            }
            if (ec && (! beyond_for))
                pr3ser(sc_powsup_pt, "was scanning when failed", ec);

        }
        // classic C for loops still useful in a case like this
        for (size_t k = 0; k < sz; ++k, prev_elemp = elemp) {
            int j;

            elemp = &op->tc_de_v[k];
            j = elemp->pd_inum_;
            if (elemp->partner_) {
                if (k > 0) {
                    prev_elemp->partner_ind_ = k;
                    process_pw_dir_mode(prev_elemp, true, clen, c);
                    b_ind += sg_scn3pr(b, blen, b_ind, "%s partner: ", c);
                    if (j > 0) {
// zzzzzzzzzzzzzzzzzzzzzz
                        b_ind += sg_scn3pr(b, blen, b_ind, "[pd%d] ", j);
                    }
                    op->summ_out_m.emplace(
                        std::make_pair(prev_elemp->port_num_, b));
                    b_ind = 0;
                } else {
                    // don't expect partner as first element
                    op->summ_out_m.emplace(
                        std::make_pair(elemp->port_num_, "logic_err"));
                    b_ind = 0;
                }
            } else {
                if (prev_elemp && (b_ind > 0)) {
                    process_pw_dir_mode(prev_elemp, false, clen, c);
                    sg_scn3pr(b, blen, b_ind, "%s", c);
                    op->summ_out_m.emplace(
                        std::make_pair(prev_elemp->port_num_, b));
                    b_ind = 0;
                }
                b_ind += sg_scn3pr(b, blen, b_ind, " port%d ",
                                   elemp->port_num_);
                if (j >= 0)
                    b_ind += sg_scn3pr(b, blen, b_ind, "[pd%d] ", j);
            }
        }       // <<<<<<<<<<<  end of long classic for loop
        // above loop needs potential cleanup on exit and that follows
        if (prev_elemp && (b_ind > 0)) {
            process_pw_dir_mode(prev_elemp, false, clen, c);
            sg_scn3pr(b, blen, b_ind, "%s", c);
            op->summ_out_m.emplace(std::make_pair(prev_elemp->port_num_, b));
        }
    } else if (sz == 1) {
        int b_ind { };
        char c[32];
        static const int clen = sizeof(c);

        elemp = &op->tc_de_v[0];
        int j = elemp->pd_inum_;

        b_ind += sg_scn3pr(b, blen, b_ind, " port%d ", elemp->port_num_);
        if (j >= 0)
            b_ind += sg_scn3pr(b, blen, b_ind, "[pd%d] ", j);
        process_pw_dir_mode(elemp, false, clen, c);
        sg_scn3pr(b, blen, b_ind, "%s", c);
        op->summ_out_m.emplace(std::make_pair(elemp->port_num_, b));
    }

    if (filter_for_port) {
        for (const auto& filt : op->filter_port_v) {
            sregex pat;

            regex_ctor_noexc(pat, filt, std::regex_constants::grep |
                                        std::regex_constants::icase, ec);
            if (ec) {
                pr3ser(filt, "filter was an unacceptable regex pattern");
                break;
            }
            for (const auto& entry : op->tc_de_v) {
                if (regex_match_noexc(entry.match_str_, pat, ec)) {
                    const unsigned int port_num = entry.port_num_;
                    if ((! entry.partner_) && (port_num < UINT32_MAX)) {
                        scout << op->summ_out_m[port_num] << "\n";
                    }
                    if (op->do_long > 0)
                        list_port(entry, op);
                } else if (ec) {
                    pr3ser(filt, "filter was an unacceptable regex pattern");
                    break;
                }
            }
        }
    } else if (op->filter_pd_v.empty()) {
        for (auto&& [n, v] : op->summ_out_m) {
            if (lsupd_verbose > 4)
                scerr << "port=" << n << ":\n";
            scout << v << "\n";
            if (op->do_long > 0) {
                for (const auto& entry : op->tc_de_v) {
                    if ((! entry.partner_) && (n == entry.port_num_))
                        list_port(entry, op);
                }
            }
        }
    }

    if (op->do_caps == 0)
        goto fini;

    if (op->filter_pd_v.empty())
        scout << "\n";

    for (fs::directory_iterator itr(sc_upd_pt, dir_opt, ec);
         (! ec) && itr != end_itr;
         beyond_for = false, itr.increment(ec) ) {
        beyond_for = true;
        const fs::path & pt { itr->path() };
        int k;

        if (itr->is_directory(ec)) {
            if (1 != sscanf(pt.filename().c_str(), "pd%d", &k))
                pr2ser("unable to find 'pd<num>' to decode");
            else {
                upd_dir_elem ue { *itr };

                ue.match_str_.assign(sstring("pd") + std::to_string(k));
                // op->upd_de_m[k] = ue;
                // op->upd_de_m.insert(std::make_pair(k, ue));
                op->upd_de_m.emplace(std::make_pair(k, ue));
            }
        } else if (ec)
            pr3ser(pt, "failed in is_directory()", ec);
    }
    if (ec && (! beyond_for))
        pr3ser(sc_upd_pt, "was scanning when failed", ec);
    if (op->upd_de_m.empty())
        goto fini;

    if (filter_for_pd) {
        for (const auto& filt : op->filter_pd_v) {
            sregex pat { filt, std::regex_constants::grep |
                               std::regex_constants::icase };
            for (auto&& [nm, upd_d_el] : op->upd_de_m) {
                if (regex_match_noexc(upd_d_el.match_str_, pat, ec)) {
                    if (lsupd_verbose > 3)
                        scerr << "nm=" << nm << ", regex match on: "
                              << upd_d_el << "\n";
                    ec = populate_src_snk_pdos(upd_d_el, op);
                    if (ec) {
                        pr3ser(upd_d_el.path(), "from populate_src_snk_pdos",
                               ec);
                        break;
                    }
                    list_pd(nm, upd_d_el, op);
                } else if (ec) {
                    pr3ser(filt, "filter was an unacceptable regex pattern");
                    break;
                }
            }
        }
    } else if (! filter_for_port) {
        for (auto&& [nm, upd_d_el] : op->upd_de_m) {
            if (lsupd_verbose > 3)
                scerr << "nm=" << nm << ", about to populate on: "
                      << upd_d_el << "\n";
            ec = populate_src_snk_pdos(upd_d_el, op);
            if (ec) {
                pr3ser(upd_d_el.path(), "from populate_src_snk_pdos", ec);
                break;
            }
            list_pd(nm, upd_d_el, op);
        }
    }

fini:
    if (jsp->pr_as_json) {
        FILE * fp = stdout;

        if (op->js_file) {
            if ((1 != strlen(op->js_file)) || ('-' != op->js_file[0])) {
                fp = fopen(op->js_file, "w");   /* truncate if exists */
                if (nullptr == fp) {
                    res = errno;
                    pr2serr("unable to open file: %s [%s]\n", op->js_file,
                            strerror(res));
                }
            }
            /* '--js-file=-' will send JSON output to stdout */
        }
        if (fp)
            sgj_js2file_estr(jsp, nullptr, res, strerror(res), fp);
        if (op->js_file && fp && (stdout != fp))
            fclose(fp);
        sgj_finish(jsp);
    }
    return res;
}
