/*
 * Copyright (c) 2023 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/* This is a utility program for listing USB-C Power Delivery ports
 * and partners in Linux. It performs data-mining in the sysfs file
 * system assumed to be mounted under /sys .
 *
 */


// Initially this utility will assume C++20 or later

static const char * const version_str = "0.90 20230703";

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
 * There are two USB standards covering this area:
 *    1) USB Type-C Cable and Connector Specification, Release 2.1
 *    2) USB Power Delivery Specification, Revision 3.1, Version 1.8
 *       - this is optional, so USB-C ports don't necessarily support PD
 *
 * USB.org's use of release, revision and version defies logic. The above
 * standard names are taken from their front pages. Interconnects complying
 * with 1) do not necessarily support 2) (i.e. PD). In the absence of PD,
 * resistors on the CC lines determine which end is the source/host and
 * which end is the the sink/device. USB PD Revision 1 is history (an
 * experiment that failed). USB PD Revision 2 introduced fixed Vbus voltages
 * up to 20 Volts and with an appropriate ("Emarked") cable could carry 5
 * Amps for 100 Watts. USB PD Revision 3 introduced the Programmably Power
 * Supply (PPS) optional capability which included current limiting (CL) by
 * the source. Then USB PD Revision 3.1 introduced "Extended Power Range"
 * (EPR) with fixed voltages at 28, 36 and 48 Volts. To avoid confusion, all
 * active PD standards prior to Revision 3.1 were dubbed "Standard Power
 * Range" (SPR). EPR also has a (sink) adjustable voltage supply (AVS) range
 * of 15 to 48 Volts _without_ current limiting.
 *
 * There are two power roles: source (power provider) and sink (power
 * consumer). USB-C power banks and laptops can often be both, but not at
 * the same time. The USB PD term for this is "Dual Role Power" (DRP)
 * but most laptops, at this time, are not true DRP in the USB PD sense;
 * they tend to fall back to USB-A 5 Volt source/host mode when talking
 * to a USB memory key which is very unlikely to support USB PD.
 * In a similar way there are two data roles: host and device. A USB PD
 * port that can play either role is called "Dual Role Data" (DRD).
 *
 * Some other related jargon is UFP for upward facing port and DFP for
 * downward facing port. The mental picture here is with the USB host at the
 * top of a hierarchy with USB devices at the bottom (i.e. the leaves) with
 * possibly a USB hub in the middle. So an UFP on a hub connects to a DFP on
 * the host (e.g. a laptop).
 */

namespace fs = std::filesystem;
using sstring=std::string;
using sregex=std::regex;
// static auto & srgx_constants { std::regex_constants };
static auto & scout { std::cout };
static auto & scerr { std::cerr };

static const fs::directory_iterator end_itr { };
static const sstring empty_str { };
static const auto dir_opt = fs::directory_options::skip_permission_denied;

int lsupd_verbose = 0;


// This struct holds directory_entry_s of port<n>[-partner] objects found
// under the /sys/class/typec/ directory.
// Assume objects of this class can outlive *itr in the directory scan that
// was used to create them.
struct tc_dir_elem : public fs::directory_entry {
    tc_dir_elem(const fs::directory_entry & bs) : fs::directory_entry(bs) { };

    bool is_partner() const { return partner_; }

    bool partner_ {false}; // mark non-static member variables with trailing _

    bool upd_dir_exists_ {false};

    int pd_inum_ {-1};

    unsigned int port_num_ {UINT32_MAX};

    sstring match_str_;
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
    enum pdo_e pdo_el_;
    bool is_source_;     // if false implies this port is sink
    uint16_t pdo_ind_;
    uint32_t raw_pdo_;
    fs::path pdo_d_p_; // for example: /.../1:fixed_supply
    // more fields or encode/decode raw_pdo?

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

// command line options and other things that would otherwaise be at file
// scope. Don't mark with trailing _
struct opts_t {
    bool do_json;
    bool verbose_given;
    bool version_given;
    int do_caps;
    int do_help;
    const char * pseudo_mount_point;
    const char * json_arg;  /* carries [JO] if any */
    const char * js_file; /* --js-file= argument */
    sgj_state json_st;  /* -j[JO] or --json[=JO] */
    // vector of sorted /sys/class/typec/*  tc_dir_elem objects
    std::vector<tc_dir_elem> tc_de_v;
    // map of <pd_num> to corresponding
    // /sys/class/usb_power_delivery/pd<pd_num> upd_dir_elem object
    std::map<int, upd_dir_elem> upd_de_m;

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
    {"sysfsroot", required_argument, 0, 'y'},
    {"verbose", no_argument, 0, 'v'},
    {"version", no_argument, 0, 'V'},
    {0, 0, 0, 0},
};

static sstring sysfs_root { "/sys" };
static const char * const upd_sn = "usb_power_delivery";
static const char * const class_s = "class";
static const char * const typec_s = "typec";
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


static const char * const usage_message1 =
    "Usage: lsupd  [--caps] [--help] [--json[=JO]] [--js-file=JFN]\n"
    "              [--sysfsroot=SPATH] [--verbose] [--version]\n"
    "              [FILTER ...]\n"
    "  where:\n"
    "    --caps|-c         list pd sink and source capabilities\n"
    "    --help|-h         this usage information\n"
    "    --json[=JO]|-j[=JO]     output in JSON instead of plain text\n"
    "                            use --json=? for JSON help\n"
    "    --js-file=JFN|-J JFN    JFN is a filename to which JSON output is\n"
    "                            written (def: stdout); truncates then "
    "writes\n"
    "    --sysfsroot=SPATH|-y SPATH    set sysfs mount point to SPATH (def: "
    "/sys)\n"
    "    --verbose|-v      increase verbosity\n"
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
pr3ser(const std::string & e1msg, const char * e2msg /* = NULL */,
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
       const char * e3msg /* = NULL */, const std::error_code & ec,
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
    const fs::path & vnm { base_name.empty() ? dir_or_fn_pt :
                                               dir_or_fn_pt / base_name };
    std::error_code ec { };

    val_out.clear();
    val_out.resize(max_value_len);
    bp = val_out.data();
    if (NULL == (f = fopen(vnm.c_str(), "r"))) {
        ec.assign(errno, std::system_category());
        return ec;
    }
    if (NULL == fgets(bp, max_value_len, f)) {
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

static std::error_code
map_reg_files(const fs::path & dir_pt, std::map<sstring, sstring> & map_io,
              bool ignore_uevent = true)
{
    bool beyond_for = false;
    std::error_code ec { };

    for (fs::directory_iterator itr(dir_pt, dir_opt, ec);
         (! ec) && itr != end_itr;
         beyond_for = false, itr.increment(ec) ) {
        beyond_for = true;
        const fs::path & pt { *itr };
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

static std::error_code
populate_pdos(const fs::path & cap_pt, bool is_source, upd_dir_elem & val,
              struct opts_t * /* op */)
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
                    pdo_elem a_pdo;

                    a_pdo.pdo_ind_ = pdo_ind;
                    a_pdo.is_source_ = is_source;
                    if (0 == strcmp(cp + 1, fixed_ln_sn))
                        a_pdo.pdo_el_ = pdo_e::pdo_fixed;
                    else if (0 == strcmp(cp + 1, batt_ln_sn))
                        a_pdo.pdo_el_ = pdo_e::pdo_battery;
                    else if (0 == strcmp(cp + 1, vari_ln_sn))
                        a_pdo.pdo_el_ = pdo_e::pdo_battery;
                    else if (0 == strcmp(cp + 1, pps_ln_sn))
                        a_pdo.pdo_el_ = pdo_e::apdo_pps;
                    else if (0 == strcmp(cp + 1, avs_ln_sn))
                        a_pdo.pdo_el_ = pdo_e::apdo_avs;
                    else
                        a_pdo.pdo_el_ = pdo_e::pdo_null;

                    a_pdo.pdo_d_p_ = pt;
                    pdo_el_v.push_back(a_pdo);
                }
            }
        }
    }
    if (ec && (! beyond_for))
        pr3ser(cap_pt, "was scanning when failed", ec);
    if (pdo_el_v.size() > 1)
        std::ranges::sort(pdo_el_v);

    if (is_source)
        val.source_pdo_v_.swap(pdo_el_v);
    else
        val.sink_pdo_v_.swap(pdo_el_v);
    return ec;

}

static std::error_code
populate_src_snk_pdos(upd_dir_elem & val, struct opts_t * op)
{
    std::error_code ec { }, ec2 { };
    fs::path pd_pt { val.path() };

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

static std::error_code
list_port(const tc_dir_elem & entry, struct opts_t * /* op */)
{
    std::error_code ec { };
    fs::path pt { entry.path() };
    sstring basename { pt.filename() };
    bool is_ptner = entry.is_partner();

    scout << (is_ptner ? "   " : "> ") << basename << ",  partner="
          << is_ptner << ",  [pd" << entry.pd_inum_ << "] :\n";
    if (entry.is_directory(ec) && entry.is_symlink(ec)) {
        const auto & slink = fs::read_symlink(entry, ec);

        if (ec) {
            pr3ser(pt, "read_symlink() failed", ec);
            return ec;
        } else if (lsupd_verbose)
            scout << "    --> " << slink << "\n";

        fs::path ppt = fs::canonical(pt, ec).parent_path();
        if (ec) {
            pr3ser(pt, "failed to canonize 3", ec);
            return ec;
        }
        if (lsupd_verbose > 3) {
            scout << "    path: " << entry << "\n";
            scout << "    parent c_path: " << ppt << "\n";
            scout << "    parent^2 c_path: " << ppt.parent_path() << "\n";
        }
        if (! entry.is_partner()) {
            std::map<sstring, sstring> map_io;

            ec = map_reg_files(pt, map_io);
            if (ec) {
                pr3ser(pt, "failed in map_reg_files()", ec);
                return ec;
            }
            for (auto&& [n, v] : map_io) {
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
list_pd(int pd_num, const upd_dir_elem & upd_d_el, struct opts_t * /* op */)
{
    std::error_code ec { };

    if (upd_d_el.source_pdo_v_.empty())
        scout << "> pd" << pd_num << ": has NO source_caps\n";
    else {
        scout << "> pd" << pd_num << ": source capabilities:\n";
        for (const auto& a_pdo : upd_d_el.source_pdo_v_) {
            std::map<sstring, sstring>  map_io;

            scout << "  >>> " << a_pdo.pdo_d_p_.filename()
                  << ", type: " << pdo_e_to_str(a_pdo.pdo_el_) << "\n";
            ec = map_reg_files(a_pdo.pdo_d_p_, map_io);
            if (ec) {
                pr3ser(a_pdo.pdo_d_p_, "failed in map_reg_files()", ec);
                break;
            }
            for (auto&& [n, v] : map_io) {
                scout << "      " << n << "='" << v << "'\n";
            }
        }
    }
    if (ec)
        return ec;

    if (upd_d_el.sink_pdo_v_.empty())
        scout << "> pd" << pd_num << ": has NO sink_caps\n";
    else {
        scout << "> pd" << pd_num << ": sink capabilities:\n";
        for (const auto& a_pdo : upd_d_el.sink_pdo_v_) {
            std::map<sstring, sstring>  map_io;

            scout << "  >>> " << a_pdo.pdo_d_p_.filename()
                  << ", type: " << pdo_e_to_str(a_pdo.pdo_el_) << "\n";
            ec = map_reg_files(a_pdo.pdo_d_p_, map_io);
            if (ec) {
                pr3ser(a_pdo.pdo_d_p_, "failed in map_reg_files()", ec);
                break;
            }
            for (auto&& [n, v] : map_io) {
                scout << "      " << n << "='" << v << "'\n";
            }
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
    bool filter_for_port = false;
    bool filter_for_pd = false;
    bool beyond_for = false;
    std::error_code ec { };
    struct opts_t opts { };
    struct opts_t * op = &opts;
    sgj_state * jsp;
    sgj_opaque_p jop = NULL;
    int c, res { };

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "^chj::J:vVy:", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'c':
            op->do_caps = true;
            break;
        case 'h':
            op->do_help = true;
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
                op->json_arg = NULL;
            break;
       case 'J':
            op->do_json = true;
            op->js_file = optarg;
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
    if (op->do_help) {
        usage();
        return 0;
    }
    if (op->version_given) {
        scout << version_str << "\n";
        return 0;
    }
    if (op->filter_port_v.size() > 0)
        filter_for_port = true;
    if (op->filter_pd_v.size() > 0)
        filter_for_pd = true;
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
        fs::path pt { op->pseudo_mount_point };

        if (! fs::exists(pt, ec)) {
            if (ec) {
                pr2ser("fs::exists error", ec);
            } else
                pr3ser(pt, "does not exist");
            return 1;
        } else if (! fs::is_directory(pt, ec)) {
            if (ec) {
                pr2ser("fs::is_directory error", ec);
            } else
                pr3ser(pt, "is not a directory");
            return 1;
        } else
            sysfs_root = pt;
    }
    sc_pt = fs::path(sysfs_root) / class_s;
    sc_typec_pt = sc_pt / typec_s;
    sc_upd_pt = sc_pt / upd_sn;

    // scout << sc_typec_pt << ":\n";

    // choose traditional for loop over range-based for, for flexibility
    for (fs::directory_iterator itr(sc_typec_pt, dir_opt, ec);
         (! ec) && itr != end_itr;
         beyond_for = false, itr.increment(ec) ) {
        beyond_for = true;
        const fs::path & it_pt { itr->path() };
        const sstring basename = it_pt.filename();

//    for (const auto& entry : fs::directory_iterator(sc_typec_pt, dir_opt,
//                                                    ec)) {
        if (lsupd_verbose > 4)
            pr3ser(basename, "filename() of entry in /sys/class/typec");
        tc_dir_elem de { *itr };
        const char * base_s = basename.data();

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
                if (! de.partner_) {
                    ec = get_value(itr->path(), "power_role", attr);

                    if (ec) {
                        pr3ser(itr->path(), "returned by get_value()", ec);
                    } else {
                        if (lsupd_verbose > 0)
                            scout << "power_role: " << attr << "\n";
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
    std::ranges::sort(op->tc_de_v);

    if (filter_for_port) {
        for (const auto& filt : op->filter_port_v) {
            sregex pat;

            regex_ctor_noexc(pat, filt, std::regex_constants::grep |
                                        std::regex_constants::icase, ec);
            if (ec) {
                    pr3ser(filt, "filter was an unacceptable regex pattern");
                    break;
                }
            // sregex pat { filt, std::regex_constants::basic |
            for (const auto& entry : op->tc_de_v) {
                if (regex_match_noexc(entry.match_str_, pat, ec))
                    list_port(entry, op);
                else if (ec) {
                    pr3ser(filt, "filter was an unacceptable regex pattern");
                    break;
                }
            }
        }
    } else if (op->filter_pd_v.empty()) {
        for (const auto& entry : op->tc_de_v) {
            list_port(entry, op);
        }
    }

    scout << "\n\n";

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
    if (op->upd_de_m.empty())
        goto fini;

    // scout << sc_upd_pt << ":\n";

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
    } else {
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
                if (NULL == fp) {
                    res = errno;
                    pr2serr("unable to open file: %s [%s]\n", op->js_file,
                            strerror(res));
                }
            }
            /* '--js-file=-' will send JSON output to stdout */
        }
        if (fp)
            sgj_js2file_estr(jsp, NULL, res, strerror(res), fp);
        if (op->js_file && fp && (stdout != fp))
            fclose(fp);
        sgj_finish(jsp);
    }
    return res;
}
