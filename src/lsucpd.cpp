/*
 * Copyright (c) 2023-2026 Douglas Gilbert.
 * All rights reserved.
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

static const char * const version_str = "0.92 20261104 [svn: r34]";

static const char * const my_name { "lsucpd: " };

#include <iostream>
#include <fstream>
#include <cstdint>
#include <filesystem>
#include <vector>
#include <map>
#include <ranges>
#include <algorithm>            // needed for ranges::sort()
#include <cstring>              // needed for strstr()
#include <cstdio>               // using sscanf()
#include <getopt.h>
#include <fnmatch.h>            // for FILTER argument

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SOURCE_LOCATION
#include <source_location>
#endif

#include "lsucpd.h"
// Bill Weinman's header library for C++20 follows. Expect to drop if moved
// to >= C++23 and then s/bw::print/std::print/ .
#include "bwprint.hpp"

/*
 * Some jargon:
 *    relative path: a path the does not start with '/'
 *    absolute path: a path that starts with '/'
 *    canonical path: an absolute path that contains no symlinks and
 *                    no specials (i.e. "." and "..")
 *                    also known as the "physical" path as in the
 *                    command 'pwd --physical'
 *    symlink: a symbolic link that often breaks the otherwise hierarchial
 *             nature of a file system, so they are evil ...
 *    symlink target: the destination of the symlink: a file, more often
 *                    a directory and may not even exist. targets are often
 *                    relative to the location of the symlink although
 *                    they may be an absolute path.
 *    dangling or hanging symlink: one whose target does not exist
 *    link name of symlink: where the symlink actually resides, when this
 *                          is given to the readlink(2) system call it
 *                          yields the corresponding symlink target.
 *    UCSI (ucsi): Usb type-C connector system Software Interface
 *
 * Each file (including directories) has a unique canonical path.
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

/* Capitalize the first letter of any class, struct, enum, or using name
 * introduced by this project. Namespaces, (member) functions and
 * variables start with a lower case letter. */

namespace fs = std::filesystem;
using Sstring=std::string;
using Sstring_vw=std::string_view;
using Svector=std::vector<Sstring>;
using Strstr_m=std::map<Sstring, Sstring>;


static const fs::directory_iterator end_itr { };
static const Sstring empty_str { };
static const auto dir_opt = fs::directory_options::skip_permission_denied;

// vector of /sys/class/power_supply/ucsi* filenames
static Svector pow_sup_ucsi_v;

int lsucpd_verbose = 0;

enum class Pw_op_mode_e {
    def = 0,    // "default": 5 Volts at 900 mA (need to confirm)
                // Is that 6 load_units ?
    v5i1_5,     // 5 Volts at "1.5A" (type C resistor setting)
    v5i3_0,     // 5 Volts at "3.0A" (type C resistor setting)
    usb_pd,     // "usb_power_delivery"
};

// This struct holds directory_entry-s of port<n>[-partner] objects found
// under the /sys/class/typec/ directory.
// Assume objects of this class can outlive *itr in the directory scan that
// was used to create them.
struct Tc_dir_elem : public fs::directory_entry {
    Tc_dir_elem(const fs::directory_entry & bs) : fs::directory_entry(bs) { };

    Tc_dir_elem() noexcept : fs::directory_entry() { };

    // Tc_dir_elem(const Tc_dir_elem & ) = delete;

    bool is_partner() const noexcept { return partner_; }

    // want sort order like this: p0, p0p, p1, p1p, p3, p3p
    bool operator<(const Tc_dir_elem & oth) const {
        if (port_num_ < oth.port_num_)
            return true;
        else if (port_num_ > oth.port_num_)
            return false;
        else if (! partner_ && oth.partner_)
            return true;
        else
            return false;
    }

    bool partner_ {false}; // mark non-static member variables with trailing _

    bool upd_dir_exists_ {false};  // corresponding pd<num> directory exists

    bool source_sink_known_ {false};
    bool is_source_ { false };

    bool data_role_known_ {false};
    bool is_host_ { false };

    Pw_op_mode_e pow_op_mode_ { Pw_op_mode_e::def };

    unsigned int port_num_ {UINT32_MAX};    // if partner: local's port number

    int pd_inum_ {-1};  // sysfs pd index number (starts from 0), def: none

    int partner_ind_ { -1 }; // only >= 0 for local ports that have partners

    Sstring match_str_;         // p<port_num>[p]

    // maps /sys/class/typec/port<num>[-partner] regular filenames to
    // contents. std::string --> std::string
    Strstr_m tc_sdir_reg_m;

    // Vector of USB device paths associated with this port, as std::string_s
    Svector tc_usb_dev_v;
};

enum class Pdo_e {
    pdo_null = 0,   // all 32 bits are zero, used a filler
    pdo_fixed,
    pdo_variable,
    pdo_battery,
    apdo_pps,     // SPR only: Vmin: 5 (was 3.3), Vmax: 21
                  // in PPS the source does current limiting (CL)
    apdo_spr_avs, // Vmin: 9; Vmax: 20  [new in PD 3.2]
    apdo_epr_avs, // Vmin: 15; Vmax: 48
                  // in AVS the source does NOT do current limiting (CL)
                  // That is why the names are different: (SPR) PPS versus
                  // (SPR/EPR) AVS
};

struct Pdo_elem {
    enum Pdo_e pdo_el_ { Pdo_e::pdo_null };
    bool is_source_caps_;
    uint16_t pdo_ind_;  // usb-c pd PDO index (starts at 1)
    uint32_t raw_pdo_;
    fs::path pdo_d_p_; // for example: /.../1:fixed_supply

    mutable Strstr_m ascii_pdo_m_;

    friend auto operator<=>(const Pdo_elem & lhs,
                            const Pdo_elem & rhs) noexcept
        { return lhs.pdo_ind_ <=> rhs.pdo_ind_; }
    friend auto operator==(const Pdo_elem & lhs,
                           const Pdo_elem & rhs) noexcept
        { return lhs.pdo_ind_ == rhs.pdo_ind_; }
};

// This struct holds directory_entry_s of pd<n> objects found under the
// the /sys/class/usb_power_delivery/ directory.
// Assume objects of this class can outlive *itr in the directory scan that
// created them.
struct Upd_dir_elem : public fs::directory_entry {
    Upd_dir_elem() = default;
    // following needed to make this object from instance of its base class
    Upd_dir_elem(const fs::directory_entry & bs, bool is_partner)
                : fs::directory_entry(bs), is_partner_(is_partner) { };

    Sstring match_str_;         // pd<pd_num>
    bool is_partner_ { };       // only used by --data (direction) option
    bool usb_comms_incapable_ { };  // only used by --data (direction) option
                                    // This setting is not reliable, override
                                    // if USB devices found.

    std::vector<Pdo_elem> source_pdo_v_;
    std::vector<Pdo_elem> sink_pdo_v_;
};

// command line options and other things that would otherwise be at file
// scope. Zero-ed just after creation. Don't mark with trailing _
struct Opts_t {
    bool build_upd_map_called;
    bool caps_given;
    bool do_data_dir;
    bool do_json;
    bool filter_for_pd;
    bool is_pdo_snk;
    bool verbose_given;
    bool version_given;
    int do_caps;
    int do_help;
    int do_long;
    int do_usb_devs;
    const char * pseudo_mount_point;
    const char * json_arg;  /* carries [JO] if any */
    const char * js_file; /* --js-file= argument */
    const char * pdo_opt_p;
    const char * rdo_opt_p;
    sgj_state json_st;  /* -j[JO] or --json[=JO] */

    // vector of sorted /sys/class/typec/*  Tc_dir_elem objects (ports)
    std::vector<Tc_dir_elem> tc_de_v;

    // map of <pd_num> to corresponding
    // /sys/class/usb_power_delivery/pd<pd_num> Upd_dir_elem object
    std::map<int, Upd_dir_elem> upd_de_m;
    // map of port_number to summary line string (without trailing \n)
    std::map<unsigned int, Sstring> summ_out_m;

    // Command line FILTER arguments
    Svector filter_v;
};

struct Do_fld_desc_t {   // 4 bytes long describing a PDO and a RDO field
    uint8_t low_pdo_bit;        // lowest bit address in <n> bit field
    uint8_t num_bits_typ;       // lower 4 bits: num_bits, upper 4 bits: type
                                // 0 --> filler as is rest of row
    uint8_t mult;               // multiplier to convert to centivolts,
                                // centiamps, centiwatts, 0 for unit-less.
                                // 0xff is for special handling
    uint8_t nam_str_off;        // index within pdo_str[] of field name
};

#define P_IT_FL_START 0x10      // first entry or first entry of new PDO
#define P_IT_FL_SINK  0x20      // sink_pdo_capability or giveback_flag=0
#define P_IT_FL_SRC   0x40      // source_pdo_capability or giveback_flag=1
#define P_IT_FL_CONT  0x80      // continue if PDO index is 1, skip otherwise


// Note that "no_argument" entries should appear in chk_short_opts
static const struct option long_options[] = {
    {"cap", no_argument, 0, 'c'},
    {"caps", no_argument, 0, 'c'},
    {"capability", no_argument, 0, 'c'},
    {"capabilities", no_argument, 0, 'c'},
    {"data", no_argument, 0, 'd'},
    {"help", no_argument, 0, 'h'},
    {"json", optional_argument, 0, '^'},    /* short option is '-j' */
    {"js-file", required_argument, 0, 'J'},
    {"js_file", required_argument, 0, 'J'},
    {"long", no_argument, 0, 'l'},
    {"pdo-snk", required_argument, 0, 'p'},
    {"pdo_snk", required_argument, 0, 'p'},
    {"pdo-sink", required_argument, 0, 'p'},
    {"pdo-src", required_argument, 0, 'P'},
    {"pdo_src", required_argument, 0, 'P'},
    {"pdo-source", required_argument, 0, 'P'},
    {"rdo", required_argument, 0, 'r'},
    {"sysfsroot", required_argument, 0, 'y'},
    {"usb", no_argument, 0, 'u'},
    {"verbose", no_argument, 0, 'v'},
    {"version", no_argument, 0, 'V'},
    {0, 0, 0, 0},
};

// Define one PDO string with embedded <null> chars. starting position
// indexes shown in comments to the right.
static const char * pdo_str[] = {
    "dual_role_power",                  // 0
    "usb_suspend_supported",
    "unconstrained_power",
    "usb_communication_capable",
    "unchunked_message_supported",      // 4
    "epr_mode_supported",
    "higher_capability",
    "fast_role_swap",
    "peak_current",                     // 8
    "voltage",
    "maximum_current",
    "operational_current",
    "maximum_voltage",                  // 12
    "minimum_voltage",
    "pps_power_limited",
    "dual_role_data",
    "maximum_power",                    // 16
    "operational_power",
    "pd_power",

    /* Following specifically for RDOs */
    "object_position",
    "giveback_flag",                    // 20
    "capability_mismatch",
    "no_usb_suspend",
    "operating_current",
    "maximum_operating_current",        // 24
    "minimum_operating_current",
    "operating_power",
    "maximum_operating_power",
    "minimum_operating_power",          // 28
    "output_voltage",
};

/* PDO and RDO field definitions based on an array of Do_fld_desc_t objects */
static const struct Do_fld_desc_t pdo_part_a[67] = {

// Start PDO entries:
/* index=0 */
    // Following block for Fixed PDOs at object position 1
    {29, 1 | P_IT_FL_START, 0, 0 /* DRP */},
    {28, 1 | P_IT_FL_SINK, 0, 6 /* HC */},
    {28, 1 | P_IT_FL_SRC, 0, 1 /* USS (Suspend supported) */},
    {27, 1 /* source+sink */, 0, 2 /* UCP (Unconstrained power) */},
    {26, 1, 0, 3 /* UCC (USB comms capable) */},
    {25, 1, 0, 15 /* DRD (Dual-Role data) */},
    {24, 1 | P_IT_FL_SRC, 0, 4 /* UCH (Unchunked ext msg support) */},
    {23, 1 | P_IT_FL_SRC, 0, 5 /* EPR (EPR mode capable) */},
    {23, 2 | P_IT_FL_SINK | P_IT_FL_CONT, 0, 7 /* FRS (Fast Role swap) */},
    // vvvvvvvvvvvvvvvvvv continue on due to P_IT_FL_CONT flag vvvvvvvvvvvvv
    // Following block for all Fixed PDOs
    {20, 2 | P_IT_FL_START | P_IT_FL_SRC, 0, 8 /* Peak current, unit-less */},
    {10, 10, 5, 9 /* V (fixed Voltage in 50 mV units) */},
    {0, 10 | P_IT_FL_SRC, 1, 10 /* Imax (in 10 mA units) */},
    {0, 10 | P_IT_FL_SINK, 1, 11 /* Ioperational (in 10 mA units) */},

/* index=13 */
    // Following block for Battery PDOs [B31..B30=01b]
    {20, 10 | P_IT_FL_START, 5, 12 /* Vmax (in 50 mV units) */},
    {10, 10, 5, 13 /* Vmin (in 50 mV units) */},
    {0, 10 | P_IT_FL_SRC, 25, 16 /* Pmax (in 250 mW units) */},
    {0, 10 | P_IT_FL_SINK, 25, 17 /* Poperational (in 250 mW units) */},

/* index=17 */
    // Following block for Variable PDOs [B31..B30=10b]
    {20, 10 | P_IT_FL_START, 5, 12 /* Vmax (in 50 mV units) */},
    {10, 10, 5, 13 /* Vmin (in 50 mV units) */},
    {0, 10 | P_IT_FL_SRC, 1, 10 /* Imax (in 10 mA units) */},
    {0, 10 | P_IT_FL_SINK, 1, 11 /* Ioperational (in 10 mA units) */},

/* index=21 */
    // Following block for PPS PDOs [B31..B28=1100b]
    {27, 1 | P_IT_FL_START | P_IT_FL_SRC, 0, 14 /* PPL (power limited) */},
    {17, 8, 10, 12 /* Vmax (in 100 mV units) */},
    {8, 8, 10, 13  /* Vmin (in 100 mV units) */},
    {0, 7 | P_IT_FL_SRC, 5, 10 /* Imax (in 50 mA units) */},
    {0, 7 | P_IT_FL_SINK, 5, 11 /* Ioperational (in 50 mA units) */},

/* index=26 */
    // Following block for AVS PDOs [B31..B28=1101b]
    {26, 2 | P_IT_FL_START | P_IT_FL_SRC, 0, 8 /* Peak current, unit-less */},
    {17, 9, 10, 12 /* Vmax (in 100 mV units) */},
    {8, 8, 10, 13  /* Vmin (in 100 mV units) */},
    {0, 8, 100, 18 /* PDP  (in 1 W units) */},  // Power Delivery Power

// Start RDO entries:
/* index=30  object position refers to partner's source PDO pack */
    // Following block for Fixed and Variable RDOs
    {28, 4 | P_IT_FL_START, 0, 19 /* Object position (1...13) valid */},
    {27, 1, 0, 20  /* GiveBack flag */},
    {26, 1, 0, 21  /* Capability mismatch */},
    {25, 1, 0, 3   /* USB comms capable */},
    {24, 1, 0, 22  /* No USB suspend */},
    {23, 1, 0, 4   /* Unchunked ext msg support */},
    {22, 1, 0, 5   /* EPR (EPR mode capable) */},
    {10, 10, 1, 23 /* Iop (in 10 mA units) */},
    {0, 10 | P_IT_FL_SINK, 1, 24 /* Imax (in 10 mA units) */},
    {0, 10 | P_IT_FL_SRC, 1, 25  /* Imin (in 10 mA units) */},

/* index=40 */
    // Following block for Battery RDOs
    {28, 4 | P_IT_FL_START, 0, 19 /* Object position (1...13) valid */},
    {27, 1, 0, 20  /* GiveBack flag */},
    {26, 1, 0, 21  /* Capability mismatch */},
    {25, 1, 0, 3   /* USB comms capable */},
    {24, 1, 0, 22  /* No USB suspend */},
    {23, 1, 0, 4   /* Unchunked ext msg support */},
    {22, 1, 0, 5   /* EPR (EPR mode capable) */},
    {10, 10, 25, 26 /* Pop (in 250 mW units) */},
    {0, 10 | P_IT_FL_SINK, 25, 27 /* Pmax (in 250 mW units) */},
    {0, 10 | P_IT_FL_SRC, 25, 28  /* Pmin (in 250 mW units) */},

/* index=50 */
    // Following block for PPS RDOs
    {28, 4 | P_IT_FL_START, 0, 19 /* Object position (1...13) valid */},
    {26, 1, 0, 21  /* Capability mismatch */},
    {25, 1, 0, 3   /* USB comms capable */},
    {24, 1, 0, 22  /* No USB suspend */},
    {23, 1, 0, 4   /* Unchunked ext msg support */},
    {22, 1, 0, 5   /* EPR (EPR mode capable) */},
    {9, 11, 2, 29  /* Output voltage (in 20 mV units) */},
    /* the following field sets the current limit for PPS */
    {0, 7, 5, 23   /* Operating current (in 50 mA units) */},

/* index=58 */
    // Following block for AVS RDOs, no current limiting supported
    {28, 4 | P_IT_FL_START, 0, 19 /* Object position (1...13) valid */},
    {26, 1, 0, 21  /* Capability mismatch */},
    {25, 1, 0, 3   /* USB comms capable */},
    {24, 1, 0, 22  /* No USB suspend */},
    {23, 1, 0, 4   /* Unchunked ext msg support */},
    {22, 1, 0, 5   /* EPR (EPR mode capable) */},   // can this be != 1 ??
    {9, 11, 0xff, 29  /* Output voltage (in 25 mV units) [special] */},
    {0, 7, 5, 23   /* Operating current (in 50 mA units) */},

/* index=66 */
    {0, 0, 0, 0},       // sentinel
};

static Sstring sysfs_root { "/sys" };
static const char * const upd_sn = "usb_power_delivery";
static const char * const class_s = "class";
static const char * const typec_s = "typec";
static const char * const powsup_sn = "power_supply";
static const char * const src_cap_s = "source-capabilities";
static const char * const sink_cap_s = "sink-capabilities";
static const char * const src_ucc_s =
        "source-capabilities/1:fixed_supply/usb_communication_capable";
static const char * const fixed_ln_sn = "fixed_supply";
static const char * const batt_ln_sn = "battery";
static const char * const vari_ln_sn = "variable_supply";
static const char * const pps_ln_sn = "programmable_supply";
// static const char * const avs_ln_sn = "adjustable_supply"; // may NEED ...
static const char * const spr_avs_ln_sn = "spr_adjustable_supply";
static const char * const epr_avs_ln_sn = "epr_adjustable_supply";
static const char * const num_alt_modes_sn = "number_of_alternate_modes";
static const char * const ct_sn = "class_typec";
static const char * const cupd_sn = "class_usb_power_delivery";
static const char * const lsucpd_internal_sn = "lsucpd_internal";

static fs::path sc_pt;
static fs::path sc_typec_pt;
static fs::path sc_upd_pt;
static fs::path sc_powsup_pt;

static inline Sstring filename_as_str(const fs::path & pt) noexcept
{
    return pt.filename().string();
}


static const char * const usage_message1 =
    "Usage: lsucpd [--caps] [--data] [--help] [--json[=JO]] [--js-file=JFN]\n"
    "              [--long] [--pdo-snk=SI_PDO[,IND]] "
    "[--pdo-src=SO_PDO[,IND]]\n"
    "              [--rdo=RDO,REF] [--sysfsroot=SPATH] [--usb] [--verbose]\n"
    "              [--version]  [FILTER ...]\n"
    "  where:\n"
    "    --caps|-c         list pd sink and source capabilities. Once: one "
    "line\n"
    "                      per capability; twice: name: 'value' pairs; "
    "three\n"
    "                      times: PDO object position 1 only (first PDO)\n"
    "    --data|-d         show USB data direction {device} <| {host}\n"
    "    --help|-h         this usage information\n"
    "    --json[=JO]|-j[=JO]     output in JSON instead of plain text\n"
    "                            use --json=? for JSON help\n"
    "    --js-file=JFN|-J JFN    JFN is a filename to which JSON output is\n"
    "                            written (def: stdout); truncates then "
    "writes\n"
    "    --long|-l         supply port attributes or PDO raw values; if "
    "given\n"
    "                      twice display partner's alternate mode "
    "information\n"
    "    --pdo-snk=SI_PDO[,IND]|-p SI_PDO[,IND]\n"
    "                      decode SI_PDO as sink PDO into component fields.\n"
    "                      if IND of 1 is given, fixed supplies have more\n"
    "                      fields (def: not 1). After decoding it exits.\n"
    "    --pdo-src=SO_PDO[,IND]|-P SO_PDO[,IND]\n"
    "                      similar to --pdo-snk= but for source PDO\n"
    "    --rdo=RDO,REF|-r RDO,REF    RDO is a 32 bit value (def: in "
    "decimal).\n"
    "                                REF is one of F|B|V|P|A for Fixed, "
    "Battery,\n"
    "                                Variable, PPS or AVS\n"
    "    --sysfsroot=SPATH|-y SPATH    set sysfs mount point to SPATH (def: "
    "/sys)\n"
    "    --usb|-u          list USB devices connected to each Type-C "
    "port.\n"
    "                      Usually USB devices are connected to the partner "
    "port\n"
    "    --verbose|-v      increase verbosity, more debug information\n"
    "    --version|-V      output version string and exit\n\n";
static const char * const usage_message2 =
    "LiSt Usb-C Power Delivery (lsucpd) information on the command line in "
    "a\ncompact form. This utility obtains that information from sysfs "
    "(under: /sys).\nFILTER arguments are optional; if present they are of "
    "the form: 'p<num>[p]'\n'or pd<num>'. The first is for matching (typec) "
    "ports and the second for\nmatching pd objects. The first form may "
    "have a trailing 'p' for matching\nits partner port. The FILTER "
    "arguments use POSIX fnmatch(FNM_EXTMATCH)\nbased (glob like) matching. "
    "Multiple FILTER arguments may be given.\n";

static void
usage() noexcept
{
    bw::print("{}", usage_message1);
    bw::print("{}", usage_message2);
}

static Sstring
pdo_e_to_str(enum Pdo_e p_e) noexcept
{
    switch (p_e) {
    case Pdo_e::pdo_fixed: return fixed_ln_sn;
    case Pdo_e::pdo_variable: return vari_ln_sn;
    case Pdo_e::pdo_battery: return batt_ln_sn;
    case Pdo_e::apdo_pps: return pps_ln_sn;
    case Pdo_e::apdo_spr_avs: return spr_avs_ln_sn;
    case Pdo_e::apdo_epr_avs: return epr_avs_ln_sn;
    default: return "no supply";
    }
}

#ifdef HAVE_SOURCE_LOCATION

// For error processing, declaration with default arguments is in lsucpd.h
void
pr2ser(int vb_ge, const std::string & emsg,
       const std::error_code & ec /* = { } */,
       const std::source_location loc /* = std::source_location::current() */)
        noexcept
{
    if (vb_ge >= lsucpd_verbose)       // vb_ge==-1 always prints
        return;
    if (emsg.size() == 0) {     /* shouldn't need location.column() */
        if (lsucpd_verbose > 1)
            bw::print(stderr, "{} {};ln={}\n", loc.file_name(),
                      loc.function_name(), loc.line());
        else
            bw::print(stderr, "pr2ser() called but no message?\n");
    } else if (ec) {
        if (lsucpd_verbose > 1)
            bw::print(stderr, "{};ln={}: {}, error: {}\n",
                      loc.function_name(), loc.line(), emsg, ec.message());
        else
            bw::print(stderr, "{}, error: {}\n", emsg, ec.message());
    } else {
        if (lsucpd_verbose > 1)
            bw::print(stderr, "{};ln={} {}\n", loc.function_name(),
                      loc.line(), emsg);
        else
            bw::print(stderr, "{}\n", emsg);
    }
}

// For error processing, declaration with default arguments is in lsucpd.h
void
pr3ser(int vb_ge, const std::string & e1msg,
       const char * e2msg /* = nullptr */,
       const std::error_code & ec,
       const std::source_location loc) noexcept
{
    if (vb_ge >= lsucpd_verbose)       // vb_ge==-1 always prints
        return;
    if (e2msg == nullptr)
        pr2ser(vb_ge, e1msg, ec, loc);
    else if (ec) {
        if (lsucpd_verbose > 1)
            bw::print(stderr, "{};ln={}: '{}': {}, error: {}\n",
                      loc.function_name(), loc.line(), e1msg, e2msg,
                      ec.message());
        else
            bw::print(stderr, "'{}': {}, error: {}\n", e1msg, e2msg,
                      ec.message());
    } else {
        if (lsucpd_verbose > 1)
            bw::print(stderr, "{};ln={}: '{}': {}\n",
                      loc.function_name(), loc.line(), e1msg, e2msg);
        else
            bw::print(stderr, "'{}': {}\n", e1msg, e2msg);
    }
}

// For error processing, declaration with default arguments is in lsucpd.h
void
pr4ser(int vb_ge, const std::string & e1msg, const std::string & e2msg,
       const char * e3msg /* = nullptr */, const std::error_code & ec,
       const std::source_location loc) noexcept
{
    if (vb_ge >= lsucpd_verbose)       // vb_ge==-1 always prints
        return;
    if (e3msg == nullptr)
        pr3ser(vb_ge, e1msg, e2msg.c_str(), ec, loc);
    else if (ec) {
        if (lsucpd_verbose > 1)
            bw::print(stderr, "{};ln={}: '{},{}': {}, error: {}\n",
                      loc.function_name(), loc.line(), e1msg, e2msg,
                      e3msg, ec.message());
        else
            bw::print(stderr, "'{},{}': {}, error: {}\n", e1msg, e2msg,
                      e3msg, ec.message());
    } else {
        if (lsucpd_verbose > 1)
            bw::print(stderr, "{};ln={}: '{},{}': {}\n",
                      loc.function_name(), loc.line(), e1msg, e2msg,
                      e3msg);
        else
            bw::print(stderr, "'{},{}': {}\n", e1msg, e2msg, e3msg);
    }
}

#else

// For error processing, declaration with default arguments is in lsucpd.h
void
pr2ser(int vb_ge, const std::string & emsg,
       const std::error_code & ec /* = { } */) noexcept
{
    if (vb_ge >= lsucpd_verbose)       // vb_ge==-1 always prints
        return;
    if (emsg.size() == 0) {     /* shouldn't need location.column() */
        if (lsucpd_verbose > 1)
            bw::print(stderr, "no location information\n");
        else
            bw::print(stderr, "pr2ser() called but no message?\n");
    } else if (ec)
        bw::print(stderr, "{}, error: {}\n", emsg, ec.message());
    else
        bw::print(stderr, "{}\n", emsg);
}

// For error processing, declaration with default arguments is in lsucpd.h
void
pr3ser(int vb_ge, const std::string & e1msg,
       const char * e2msg /* = nullptr */,
       const std::error_code & ec) noexcept
{
    if (vb_ge >= lsucpd_verbose)       // vb_ge==-1 always prints
        return;
    if (e2msg == nullptr)
        pr2ser(vb_ge, e1msg, ec);
    else if (ec)
        bw::print(stderr, "'{}': {}, error: {}\n", e1msg, e2msg,
                  ec.message());
    else
        bw::print(stderr, "'{}': {}\n", e1msg, e2msg);
}

// For error processing, declaration with default arguments is in lsucpd.h
void
pr4ser(int vb_ge, const std::string & e1msg, const std::string & e2msg,
       const char * e3msg /* = nullptr */, const std::error_code & ec)
       noexcept
{
    if (vb_ge >= lsucpd_verbose)       // vb_ge==-1 always prints
        return;
    if (e3msg == nullptr)
        pr3ser(vb_ge, e1msg, e2msg.c_str(), ec);
    else if (ec)
        bw::print(stderr, "'{},{}': {}, error: {}\n", e1msg, e2msg,
                  e3msg, ec.message());
    else
        bw::print(stderr, "'{},{}': {}\n", e1msg, e2msg, e3msg);
}

#endif

// If base_name.empty() is true, just use dir_or_fn_pt as name. If good and
// last char in val_out is '\n' then erase it. Returns errno in ec.value()
// if ec() is true (and clears val_out), else returns false for good fetch.
static std::error_code
get_value(const fs::path & dir_or_fn_pt, const Sstring & base_name,
          Sstring & val_out, int max_value_len = 32) noexcept
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
        print_err(6, "{}: unable to fopen: {}\n", __func__, vnm.string());
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
    // val_out = std::move( Sstring { bp, len } );
    val_out.assign(bp, len);
    fclose(f);
    return ec;
}

/* If returned ec.value() is 0 (good return) then the directory dir_pt
 * has been scanned and all regular file names with the corresponding
 * contents form a pair inserted into map_io. Hidden files (files starting
 * with ".") are skipped. Only the first 32 bytes of each file are read. */
static std::error_code
map_d_regu_files(const fs::path & dir_pt, Strstr_m & map_io,
              bool ignore_uevent = true) noexcept
{
    std::error_code ecc { };
    std::error_code ec { };

    if (! map_io.empty()) {
        pr3ser(4, dir_pt, "<< for this path, contents already mapped");
        return ecc;
    }

    pr3ser(5, dir_pt, "<< directory search for regular files");
    for (fs::directory_iterator itr(dir_pt, dir_opt, ecc);
         (! ecc) && itr != end_itr;
         itr.increment(ecc) ) {
        const fs::path & pt { itr->path() };
        const Sstring name { filename_as_str(pt) };
        Sstring val;

        pr3ser(5, name, "<<< found");
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
    if (ecc) {
        pr3ser(-1, dir_pt, "<< was scanning when failed", ec);
        ec = ecc;
    }
    return ec;
}

// Expect to find keys: "power_role" and "power_operation_mode" in 'm'.
static bool
query_power_dir(const Strstr_m & m, bool & is_source,
                Pw_op_mode_e & pom) noexcept
{
    bool res = false;
    const auto it { m.find("power_role") };

    if (it != m.end()) {
        if (strstr(it->second.c_str(), "[source]"))
            is_source = true;
        else if (strstr(it->second.c_str(), "[sink]"))
            is_source = false;
        else if (lsucpd_verbose > 0) {
            is_source = false;
            pr3ser(-1, it->second, "<< unexpected power_role");
        }
        res = true;
    } else
        is_source = false;

    const auto it2 = m.find("power_operation_mode");
    if (it2 != m.end()) {
        res = true;
        if (strstr(it2->second.c_str(), "default"))
            pom = Pw_op_mode_e::def;
        else if (strstr(it2->second.c_str(), "1.5"))
            pom = Pw_op_mode_e::v5i1_5;
        else if (strstr(it2->second.c_str(), "3.0"))
            pom = Pw_op_mode_e::v5i3_0;
        else if (strstr(it2->second.c_str(), "power_delivery"))
            pom = Pw_op_mode_e::usb_pd;
        else {
            pr3ser(0, it2->second, "<< unexpected power_operation_mode");
            pom = Pw_op_mode_e::def;
        }
    } else
        pom = Pw_op_mode_e::def;
    return res;
}

// Returns true if "data_role" found in map m. If it is, sets is_host to
// true if '[host]' found in value associated with "data_role" else sets
// is_host to false; if not found sets is_host to false.
static bool
query_data_dir(const Strstr_m & m, bool & is_host) noexcept
{
    bool res = false;
    const auto it { m.find("data_role") };

    if (it != m.end()) {
        if (strstr(it->second.c_str(), "[host]"))
            is_host = true;
        else if (strstr(it->second.c_str(), "[device]"))
            is_host = false;
        else {
            is_host = false;
            pr3ser(0, it->second, "<< unexpected data_role");
        }
        res = true;
    } else
        is_host = false;
    return res;
}

static unsigned int
get_millivolts(const Sstring & name, const Strstr_m & m) noexcept
{
    unsigned int mv;
    const Strstr_m::const_iterator it = m.find(name);

    if ((it != m.end()) && (1 == sscanf(it->second.c_str(), "%umV", &mv)))
        return mv;
    return 0;
}

static unsigned int
get_milliamps(const Sstring & name, const Strstr_m & m) noexcept
{
    unsigned int ma;
    const Strstr_m::const_iterator it = m.find(name);

    if ((it != m.end()) && (1 == sscanf(it->second.c_str(), "%umA", &ma)))
        return ma;
    return 0;
}

static unsigned int
get_milliwatts(const Sstring & name, const Strstr_m & m) noexcept
{
    unsigned int mw;
    const Strstr_m::const_iterator it = m.find(name);

    if ((it != m.end()) && (1 == sscanf(it->second.c_str(), "%umW", &mw)))
        return mw;
    return 0;
}

static unsigned int
get_unitless(const Sstring & name, const Strstr_m & m) noexcept
{
    unsigned int mv;
    const Strstr_m::const_iterator it = m.find(name);

    if ((it != m.end()) && (1 == sscanf(it->second.c_str(), "%u", &mv)))
        return mv;
    return 0;
}

static void
build_raw_pdo(const fs::path & pt, Pdo_elem & a_pdo) noexcept
{
    bool src_caps { a_pdo.is_source_caps_ };
    unsigned int mv, ma, mw;
    uint32_t r_pdo { };
    uint32_t v;
    std::error_code ec { map_d_regu_files(pt, a_pdo.ascii_pdo_m_) };

    if (ec) {
        pr3ser(-1, pt, "failed in map_d_regu_files()", ec);
        a_pdo.raw_pdo_ = 0;
        return;
    }
    const auto & ss_map { a_pdo.ascii_pdo_m_ };

    if (ss_map.empty()) {
        a_pdo.raw_pdo_ = 0;
        return;
    }
    Strstr_m::const_iterator it;
    const Strstr_m::const_iterator it_end { };

    switch (a_pdo.pdo_el_) {
    case Pdo_e::pdo_fixed:      // B31...B30: 00b
        ma = get_milliamps(src_caps ? "maximum_current" :
                                      "operational_current", ss_map);
        r_pdo = (ma / 10) & 0x3ff;
        mv = get_millivolts("voltage", ss_map);
        r_pdo |= ((mv / 50) & 0x3ff) << 10;
        if (a_pdo.pdo_ind_ == 1) {      // only pdo 1 sets bits 23 to 29
            if (src_caps) {
// epr_capable at bit 23 should be here for a fixed 5V source
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
    case Pdo_e::pdo_battery:    // B31...B30: 01b
        r_pdo = 1 << 30;
        mw = get_milliwatts(src_caps ? "maximum_allowable_power" :
                                       "operational_power", ss_map);
        r_pdo |= (mw / 250) & 0x3ff;
        mv = get_millivolts("minimum_voltage", ss_map);
        r_pdo |= ((mv / 50) & 0x3ff) << 10;
        mv = get_millivolts("maximum_voltage", ss_map);
        r_pdo |= ((mv / 50) & 0x3ff) << 20;
        break;
    case Pdo_e::pdo_variable:   // B31...B30: 10b
        r_pdo = 1 << 31;
        ma = get_milliamps(src_caps ? "maximum_current" :
                                      "operational_current", ss_map);
        r_pdo |= (ma / 10) & 0x3ff;
        mv = get_millivolts("minimum_voltage", ss_map);
        r_pdo |= ((mv / 50) & 0x3ff) << 10;
        mv = get_millivolts("maximum_voltage", ss_map);
        r_pdo |= ((mv / 50) & 0x3ff) << 20;
        break;
    case Pdo_e::apdo_pps:       // APDO: B31...B30: 11b; B29...B28: 00b [SPR]
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
    case Pdo_e::apdo_spr_avs:   // APDO: B31...B30: 11b; B29...B28: 10b [SPR]
        break;
    case Pdo_e::apdo_epr_avs:   // APDO: B31...B30: 11b; B29...B28: 01b [EPR]
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

static Sstring
build_summary_s(const Pdo_elem & a_pdo, struct Opts_t * op,
                sgj_opaque_p jop) noexcept
{
    bool src_caps { a_pdo.is_source_caps_ };
    unsigned int mv, mv_min, ma, mw;
    uint32_t v;
    sgj_state * jsp { &op->json_st };
    const char * ccp;
    const auto & pt { a_pdo.pdo_d_p_ };
    std::error_code ec { map_d_regu_files(pt, a_pdo.ascii_pdo_m_) };
    static const char * v_sn = "voltage";
    static const char * max_v_sn = "maximum_voltage";
    static const char * min_v_sn = "minimum_voltage";
    static const char * max_a_sn = "maximum_current";
    static const char * op_a_sn = "operational_current";
    static const char * pk_a_sn = "peak_current";
    static const char * max_all_p_sn = "maximum_allowable_power";
    static const char * op_p_sn = "operational_power";
    static const char * ppl_sn = "pps_power_limited";
    static const char * pdp_sn = "pdp";
    static const char * u_mv_s = "unit: milliVolt";
    static const char * u_ma_s = "unit: milliAmp";
    static const char * u_mw_s = "unit: milliWatt";

    if (ec) {
        pr3ser(-1, pt, "failed in map_d_regu_files()", ec);
        return "";
    }
    const auto & ss_map { a_pdo.ascii_pdo_m_ };

    if (ss_map.empty())
        return "";
    Strstr_m::const_iterator it;
    const Strstr_m::const_iterator it_end { };

    switch (a_pdo.pdo_el_) {
    case Pdo_e::pdo_fixed:      // B31...B30: 00b
        mv = get_millivolts(v_sn, ss_map);
        sgj_js_nv_ihex_nex(jsp, jop, v_sn, mv, false, u_mv_s);
        ccp = src_caps ? max_a_sn : op_a_sn;
        ma = get_milliamps(ccp, ss_map);
        sgj_js_nv_ihex_nex(jsp, jop, ccp, ma, false, u_ma_s);
        return fmt_to_str("fixed: {}.{:02} Volts, {}.{:02} Amps ({})",
                          mv / 1000, (mv % 1000) / 10, ma / 1000,
                          (ma % 1000) / 10, (src_caps ? "max" : "op"));
    case Pdo_e::pdo_battery:    // B31...B30: 01b
        ccp = src_caps ? max_all_p_sn : op_p_sn;
        mw = get_milliwatts(ccp, ss_map);
        sgj_js_nv_ihex_nex(jsp, jop, ccp, mw, false, u_mw_s);
        mv_min = get_millivolts(min_v_sn, ss_map);
        sgj_js_nv_ihex_nex(jsp, jop, min_v_sn, mv_min, false, u_mv_s);
        mv = get_millivolts(max_v_sn, ss_map);
        sgj_js_nv_ihex_nex(jsp, jop, max_v_sn, mv, false, u_mv_s);
        return fmt_to_str("battery: {}.{:02} to {}.{:02} Volts, "
                          "{}.{:02} Watts ({})",
                          mv_min / 1000, (mv_min % 1000) / 10,
                          mv / 1000, (mv % 1000) / 10,
                          mw / 1000, (mw % 1000) / 10,
                          (src_caps ? "max" : "op"));
    case Pdo_e::pdo_variable:   // B31...B30: 10b
        ccp = src_caps ? max_a_sn : op_a_sn;
        ma = get_milliamps(ccp, ss_map);
        sgj_js_nv_ihex_nex(jsp, jop, ccp, ma, false, u_ma_s);
        mv_min = get_millivolts(min_v_sn, ss_map);
        sgj_js_nv_ihex_nex(jsp, jop, min_v_sn, mv_min, false, u_mv_s);
        mv = get_millivolts(max_v_sn, ss_map);
        sgj_js_nv_ihex_nex(jsp, jop, max_v_sn, mv, false, u_mv_s);
        return fmt_to_str("variable: {}.{:02} to {}.{:02} Volts, "
                          "{}.{:02} Amps ({})",
                          mv_min / 1000, (mv_min % 1000) / 10,
                          mv / 1000, (mv % 1000) / 10,
                          ma / 1000, (ma % 1000) / 10,
                          (src_caps ? "max" : "op"));
    case Pdo_e::apdo_pps:       // APDO: B31...B30: 11b; B29...B28: 00b [SPR]
        ma = get_milliamps(max_a_sn, ss_map);
        sgj_js_nv_ihex_nex(jsp, jop, max_a_sn, ma, false, u_ma_s);
        mv_min = get_millivolts(min_v_sn, ss_map);
        sgj_js_nv_ihex_nex(jsp, jop, min_v_sn, mv_min, false, u_mv_s);
        mv = get_millivolts(max_v_sn, ss_map);
        sgj_js_nv_ihex_nex(jsp, jop, max_v_sn, mv, false, u_mv_s);
        v = (src_caps ? get_unitless(ppl_sn, ss_map) : 0);
        if (src_caps)
            sgj_js_nv_ihex_nex(jsp, jop, ppl_sn, v, false,
                               "Pps Power Limited");
        return fmt_to_str("pps: {}.{:02} to {}.{:02} Volts, "
                          "{}.{:02} Amps (max){}",
                          mv_min / 1000, (mv_min % 1000) / 10,
                          mv / 1000, (mv % 1000) / 10,
                          ma / 1000, (ma % 1000) / 10,
                          (v ? " [PL]" : ""));
    case Pdo_e::apdo_spr_avs:   // APDO: B31...B30: 11b; B29...B28: 10b [SPR]
    case Pdo_e::apdo_epr_avs:   // APDO: B31...B30: 11b; B29...B28: 01b [EPR]
        mw = get_milliwatts(pdp_sn, ss_map);
        sgj_js_nv_ihex_nex(jsp, jop, pdp_sn, mw, false, u_mw_s);
        mv_min = get_millivolts(min_v_sn, ss_map);
        sgj_js_nv_ihex_nex(jsp, jop, min_v_sn, mv_min, false, u_mv_s);
        mv = get_millivolts(max_v_sn, ss_map);
        sgj_js_nv_ihex_nex(jsp, jop, max_v_sn, mv, false, u_mv_s);
        mv = get_millivolts("maximum_voltage", ss_map);
        v = (src_caps ? get_unitless(pk_a_sn, ss_map) : 0);
        if (src_caps)
            sgj_js_nv_ihex_nex(jsp, jop, pk_a_sn, v, false, "unitless");
        return fmt_to_str("avs: {}.{:02} to {}.{:02} Volts, "
                          "{}.{:02} Watts, Peak current setting {}",
                          mv_min / 1000, (mv_min % 1000) / 10,
                          mv / 1000, (mv % 1000) / 10,
                          mw / 1000, (mw % 1000) / 10, v);
    default:
        return "";
    }
}

static std::error_code
populate_pdos(const fs::path & cap_pt, bool is_source_caps,
              Upd_dir_elem & val, const struct Opts_t * op) noexcept
{
    std::error_code ecc { };
    std::vector<Pdo_elem> pdo_el_v;

    for (fs::directory_iterator itr(cap_pt, dir_opt, ecc);
         (! ecc) && itr != end_itr;
         itr.increment(ecc) ) {
        const fs::path & pt { *itr };
        const Sstring name { filename_as_str(pt) };

        if ((! name.empty()) && (isdigit(name[0]))) {
            int pdo_ind;
            const char * dp = name.data();

            if (1 == sscanf(dp, "%d", &pdo_ind)) {
                const char * cp = strchr(dp, ':');

                if (cp) {
                    Pdo_elem a_pdo { };

                    a_pdo.pdo_ind_ = pdo_ind;
                    a_pdo.is_source_caps_ = is_source_caps;
                    if (0 == strcmp(cp + 1, fixed_ln_sn))
                        a_pdo.pdo_el_ = Pdo_e::pdo_fixed;
                    else if (0 == strcmp(cp + 1, batt_ln_sn))
                        a_pdo.pdo_el_ = Pdo_e::pdo_battery;
                    else if (0 == strcmp(cp + 1, vari_ln_sn))
                        a_pdo.pdo_el_ = Pdo_e::pdo_variable;
                    else if (0 == strcmp(cp + 1, pps_ln_sn))
                        a_pdo.pdo_el_ = Pdo_e::apdo_pps;
                    else if (0 == strcmp(cp + 1, spr_avs_ln_sn))
                        a_pdo.pdo_el_ = Pdo_e::apdo_spr_avs;
                    else if (0 == strcmp(cp + 1, epr_avs_ln_sn))
                        a_pdo.pdo_el_ = Pdo_e::apdo_epr_avs;
                    else
                        a_pdo.pdo_el_ = Pdo_e::pdo_null;

                    a_pdo.pdo_d_p_ = pt;
                    if (op->do_long > 0)
                        build_raw_pdo(pt, a_pdo);
                    pdo_el_v.push_back(a_pdo);
                }
            }
        }
    }
    if (ecc)
        pr3ser(-1, cap_pt, "was scanning when failed", ecc);
    if (pdo_el_v.size() > 1)
        std::ranges::sort(pdo_el_v, {}, &Pdo_elem::pdo_ind_);

    if (is_source_caps)
        val.source_pdo_v_.swap(pdo_el_v);
    else
        val.sink_pdo_v_.swap(pdo_el_v);
    return ecc;
}

static std::error_code
populate_src_snk_pdos(Upd_dir_elem & val, const struct Opts_t * op) noexcept
{
    std::error_code ec { }, ec2 { };
    const fs::path & pd_pt { val.path() };

    const auto src_cap_pt = pd_pt / src_cap_s;
    if (fs::exists(src_cap_pt, ec)) {
        pr3ser(3, src_cap_pt, "exists");
        ec = populate_pdos(src_cap_pt, true, val, op);
    }
    const auto sink_cap_pt = pd_pt / sink_cap_s;
    if (fs::exists(sink_cap_pt, ec)) {
        pr3ser(3, sink_cap_pt, "exists");
        ec2 = populate_pdos(sink_cap_pt, false, val, op);
    }
    print_err(4, "Number of source PDOs: {}, number of sink PDOs: {}\n",
              val.source_pdo_v_.size(), val.sink_pdo_v_.size());
    return ec ? ec : ec2;
}

static const char * tc_pom_def = "{5V, 0.9A}";
static const char * tc_pom_5v1_5a = "{5V, 1.5A}";
static const char * tc_pom_5v3_0a = "{5V, 3.0A}";

static const char *
process_pw_d_dir_mode(const Tc_dir_elem * elemp, bool is_partn, int clen,
                      char * c, bool data_dir) noexcept
{
    const bool dd { data_dir && elemp->data_role_known_ };
    const auto & pom { elemp->pow_op_mode_ };
    const char * resp = nullptr;
    static const char * dir_tail { "====" };
    static const char * s_tail { "==" };
    static const char * p_left { "<|" };
    static const char * p_right { "|>" };

    if (pom == Pw_op_mode_e::usb_pd) {
        if (elemp->source_sink_known_) {
            if (is_partn) {
                if (elemp->is_source_) {
                    if (dd && elemp->is_host_)
                        snprintf(c, clen, " %s%s>> ", p_right, s_tail);
                    else if (dd && (! elemp->is_host_))
                        snprintf(c, clen, " %s%s>> ", p_left, s_tail);
                    else
                        snprintf(c, clen, " %s>> ", dir_tail);
                } else {
                    if (dd && elemp->is_host_)
                        snprintf(c, clen, " <<%s%s ", s_tail, p_right);
                    else if (dd && (! elemp->is_host_))
                        snprintf(c, clen, " <<%s%s ", s_tail, p_left);
                    else
                        snprintf(c, clen, " <<%s ", dir_tail);
                }
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
            case Pw_op_mode_e::def:
                resp = tc_pom_def;
                break;
            case Pw_op_mode_e::v5i1_5:
                resp = tc_pom_5v1_5a;
                break;
            case Pw_op_mode_e::v5i3_0:
                resp = tc_pom_5v3_0a;
                break;
           default:
                if (lsucpd_verbose > 0)
                    pr2serr("unexpected power_operation_mode "
                            "[%d]\n",
                            static_cast<int>(pom));
                break;
            }
            if (elemp->partner_ind_ < 0) {
                snprintf(c, clen, " <> ");
                resp = nullptr;
            } else if (dd)
                snprintf(c, clen, " %s%s>> ", p_right, s_tail);
            else
                snprintf(c, clen, " %s>> ", dir_tail);
        } else {  /* not host and not PD */
            // snprintf(c, clen, " <     ");
            if (elemp->partner_ind_ < 0)
                snprintf(c, clen, " <> ");
            else if (dd)
                snprintf(c, clen, " <<%s%s ", s_tail, p_left);
            else
                snprintf(c, clen, " <<%s ", dir_tail);
        }
    } else
        snprintf(c, clen, "   ");
    return resp;
}

static bool
pd_is_partner(int pd_inum, const struct Opts_t * op) noexcept
{
    for (const auto& entry : op->tc_de_v) {
        if (pd_inum == entry.pd_inum_)
            return entry.is_partner();
    }
    return false;
}

static std::error_code
list_port(const Tc_dir_elem & entry, struct Opts_t * op,
          sgj_opaque_p jop) noexcept
{
    bool want_alt_md = (op->do_long > 1);
    unsigned int n_a_m { };
    std::error_code ec { };
    sgj_state * jsp { &op->json_st };
    sgj_opaque_p jo2p;
    sgj_opaque_p jap;
    const fs::path & pt { entry.path() };
    const Sstring basename { filename_as_str(pt) };
    const bool is_ptner = entry.is_partner();

    if (entry.pd_inum_ >= 0) {
        sgj_hr_pri(jsp, "{}{}  [pd{}]:\n", (is_ptner ? "   " : "> "),
                   basename, entry.pd_inum_);
    } else {
        sgj_hr_pri(jsp, "{}{}:\n", (is_ptner ? "   " : "> "), basename);
    }
    if (entry.is_directory(ec) && entry.is_symlink(ec)) {
        for (auto&& [n, v] : entry.tc_sdir_reg_m) {
            sgj_hr_pri(jsp, "      {}='{}'\n", n, v);
            sgj_js_nv_s(jsp, jop, n.c_str(), v.c_str());
            if (want_alt_md && (n == num_alt_modes_sn)) {
                /* only one should match, need to visit the rest */
                if (1 != sscanf(v.c_str(), "%u", &n_a_m)) {
                    print_err(1, "unable to decode {}\n", num_alt_modes_sn);
                    continue;
                }
            }
        }
        if (n_a_m > 0) {
            jap = sgj_named_subarray_r(jsp, jop, "alternate_mode_list");
            for (unsigned int k = 0; k < n_a_m; ++k) {
                const auto alt_md_pt { entry.path() /
                            Sstring(basename + "." + std::to_string(k)) };
                if (fs::is_directory(alt_md_pt, ec)) {
                    Strstr_m nv_m;

                    jo2p = sgj_new_unattached_object_r(jsp);
                    ec = map_d_regu_files(alt_md_pt, nv_m);
                    sgj_hr_pri(jsp, "      Alternate mode: {}\n",
                               alt_md_pt.string());
                    if (! ec) {
                        for (auto&& [n, v] : nv_m) {
                            sgj_hr_pri(jsp, "        {}='{}'\n", n, v);
                            sgj_js_nv_s(jsp, jo2p, n.c_str(), v.c_str());
                        }
                    }
                    sgj_js_nv_o(jsp, jap, nullptr, jo2p);
                }
            }
        }
    } else {
        if (ec)
            pr3ser(-1, pt, "not symlink to directory", ec);
    }

    return ec;
}

static std::error_code
list_pd(int pd_num, const Upd_dir_elem & upd_d_el,
        struct Opts_t * op, sgj_opaque_p jop) noexcept
{
    std::error_code ec { };
    sgj_state * jsp { &op->json_st };
    sgj_opaque_p jo2p { };
    sgj_opaque_p jo3p { };
    Sstring s { "pd" + std::to_string(pd_num) };

    if (upd_d_el.source_pdo_v_.empty())
        sgj_hr_pri(jsp, "> pd{}: has NO {}\n", pd_num, src_cap_s);
    else {
        jo2p = sgj_snake_named_subobject_r(jsp, jop, src_cap_s);
        sgj_hr_pri(jsp, "> pd{}: {}:\n", pd_num, src_cap_s);
        for (const auto& a_pdo : upd_d_el.source_pdo_v_) {
            const Sstring pdo_nm { filename_as_str(a_pdo.pdo_d_p_) };

            jo3p = sgj_snake_named_subobject_r(jsp, jo2p, pdo_nm.c_str());
            if (op->do_caps == 1) {
                sgj_hr_pri(jsp, "  >> {}; {}\n", pdo_nm,
                           build_summary_s(a_pdo, op, jo3p));
                if (op->do_long > 0)
                    sgj_hr_pri(jsp, "        raw_pdo: 0x{:08x}\n",
                               a_pdo.raw_pdo_);
                continue;
            } else if (op->do_caps > 2) {
                if (a_pdo.pdo_ind_ > 1)
                    continue;
            }
            if (op->do_long > 0)
                sgj_hr_pri(jsp, "  >> {}, type: {}\n", pdo_nm,
                           pdo_e_to_str(a_pdo.pdo_el_));
            else
                sgj_hr_pri(jsp, "  >> {}\n", pdo_nm);
            if (a_pdo.ascii_pdo_m_.empty()) {
                Strstr_m  map_io;

                ec = map_d_regu_files(a_pdo.pdo_d_p_, map_io);
                if (ec) {
                    pr3ser(-1, a_pdo.pdo_d_p_, "failed in "
                           "map_d_regu_files()", ec);
                    break;
                }
                for (auto&& [n, v] : map_io) {
                    sgj_hr_pri(jsp, "      {}='{}'\n", n, v);
                    sgj_js_nv_s(jsp, jo3p, n.c_str(), v.c_str());
                }
            } else {
                for (auto&& [n, v] : a_pdo.ascii_pdo_m_) {
                    sgj_hr_pri(jsp, "      {}='{}'\n", n, v);
                    sgj_js_nv_s(jsp, jo3p, n.c_str(), v.c_str());
                }
            }
            if (op->do_long > 0)
                sgj_hr_pri(jsp, "        raw_pdo: 0x{:08x}\n",
                           a_pdo.raw_pdo_);
        }
    }
    if (ec)
        return ec;

    // Put extra space before pd{} and >>
    if (upd_d_el.sink_pdo_v_.empty())
        sgj_hr_pri(jsp, ">  pd{}: has NO {}\n", pd_num, sink_cap_s);
    else {
        jo2p = sgj_snake_named_subobject_r(jsp, jop, sink_cap_s);
        sgj_hr_pri(jsp, ">  pd{}: {}:\n", pd_num, sink_cap_s);
        for (const auto & a_pdo : upd_d_el.sink_pdo_v_) {
            const Sstring pdo_nm { filename_as_str(a_pdo.pdo_d_p_) };

            jo3p = sgj_snake_named_subobject_r(jsp, jo2p, pdo_nm.c_str());
            if (op->do_caps == 1) {
                sgj_hr_pri(jsp, "   >> {}; {}\n", pdo_nm,
                           build_summary_s(a_pdo, op, jo3p));
                if (op->do_long > 0)
                    sgj_hr_pri(jsp, "        raw_pdo: 0x{:08x}\n",
                               a_pdo.raw_pdo_);
                continue;
            } else if (op->do_caps > 2) {
                if (a_pdo.pdo_ind_ > 1)
                    continue;
            }
            if (op->do_long > 0)
                sgj_hr_pri(jsp, "   >> {}, type: {}\n", pdo_nm,
                          pdo_e_to_str(a_pdo.pdo_el_));
            else
                sgj_hr_pri(jsp, "   >> {}\n", pdo_nm);
            if (a_pdo.ascii_pdo_m_.empty()) {
                Strstr_m  map_io;

                ec = map_d_regu_files(a_pdo.pdo_d_p_, map_io);
                if (ec) {
                    pr3ser(-1, a_pdo.pdo_d_p_, "failed in "
                           "map_d_regu_files()", ec);
                    break;
                }
                for (auto&& [n, v] : map_io) {
                    sgj_hr_pri(jsp, "      {}='{}'\n", n, v);
                    sgj_js_nv_s(jsp, jo3p, n.c_str(), v.c_str());
                }
            } else {
                for (auto&& [n, v] : a_pdo.ascii_pdo_m_) {
                    sgj_hr_pri(jsp, "      {}='{}'\n", n, v);
                    sgj_js_nv_s(jsp, jo3p, n.c_str(), v.c_str());
                }
            }
            if (op->do_long > 0)
                sgj_hr_pri(jsp, "        raw_pdo: 0x{:08x}\n", a_pdo.raw_pdo_);
        }
    }
    return ec;
}

// Given a path to a port<n>[-partner] directory in /sys find all
// sub-directories that match the glob pattern in the filt argument.
// For example "+([0-9])-+([0-9])*" matches "3-5". Push matches onto the
// back of the match_v vector. So match_v may need to be cleared before
// this function is invoked.
static std::error_code
scan_for_usb_devs(const fs::path & port_de, const Sstring & filt,
                  Svector & match_v) noexcept
{
    std::error_code ec { };
    std::error_code ecc { };
    int res;

    for (fs::directory_iterator itr(port_de, dir_opt, ecc);
         (! ecc) && itr != end_itr;
         itr.increment(ecc) ) {
        const fs::path & pt { itr->path() };
        const Sstring & fn { filename_as_str(pt) };

        if (itr->is_directory(ec)) {
            res = fnmatch(filt.c_str(), fn.c_str(), FNM_EXTMATCH);
            if (0 == res) {
                pr3ser(4, fn, "<<< matched", { });
                match_v.push_back(pt);
            } else if (res != FNM_NOMATCH)
                print_err(-1, "{}: failed in fnmatch(), string: {}",
                          __func__, fn);
        } else if (ec)
            pr3ser(-1, pt, "failed in is_directory()", ec);
    }
    if (ecc)
        pr3ser(-1, filename_as_str(port_de), "directory_iterator failed", ecc);
    return ecc;
}

/* Populates op->tc_de_v[0..n-1] {vector of 'struct Tc_dir_elem' objects} with
 * initial class/typec sysfs information. Any users of op->tc_de_v[0..n-1]
 * need this function called first. */
static std::error_code
scan_for_typec_obj(bool & ucsi_psup_possible, struct Opts_t * op) noexcept
{
    std::error_code ec { };
    std::error_code ecc { };    // only use for directory_iterator failure

    // choose traditional for loop over range-based for, for flexibility
    for (fs::directory_iterator itr(sc_typec_pt, dir_opt, ecc);
         (! ecc) && itr != end_itr;
         itr.increment(ecc) ) {
        const fs::path & it_pt { itr->path() };
        const Sstring basename = it_pt.filename();

        pr3ser(4, basename, "filename() of entry in /sys/class/typec");
        const char * base_s = basename.data();
        Tc_dir_elem de { *itr };

        if (itr->is_directory(ec) && itr->is_symlink(ec)) {
            if (1 != sscanf(base_s, "port%u", &de.port_num_)) {
                pr3ser(0, it_pt, "unable to decode 'port<num>', skip");
                continue;
            } else {
                de.match_str_ = Sstring("p") + std::to_string(de.port_num_);
                if (strstr(base_s, "partner")) {
                    // needs C++23: if (basename.contains("partner"))
                    ec = map_d_regu_files(it_pt, de.tc_sdir_reg_m);
                    if (ec) {
                        pr3ser(-1, it_pt, "failed in map_d_regu_files()", ec);
                        continue;
                    }
                    de.partner_ = true;
                    de.match_str_ += "p";
                } else {
                    ec = map_d_regu_files(it_pt, de.tc_sdir_reg_m);
                    if (ec) {
                        pr3ser(-1, it_pt, "failed in map_d_regu_files()", ec);
                        continue;
                    }
                    de.source_sink_known_ = query_power_dir(de.tc_sdir_reg_m,
                                                            de.is_source_,
                                                            de.pow_op_mode_);
                    de.data_role_known_ = query_data_dir(de.tc_sdir_reg_m,
                                                         de.is_host_);
                }
            }
            if (op->do_usb_devs > 0) {
                de.tc_usb_dev_v.clear();
                scan_for_usb_devs(de, "+([0-9])-+([0-9])*", de.tc_usb_dev_v);
            }
            fs::path pt { it_pt / upd_sn };

            if (fs::exists(pt, ec)) {
                Sstring attr;
                int k;

                de.upd_dir_exists_ = true;
                fs::path c_pt { fs::canonical(pt, ec) };
                if (ec) {
                    pr3ser(-1, pt, "failed to canonize", ec);
                    continue;
                }
                Sstring pd_x { c_pt.filename() };
                if (1 != sscanf(pd_x.c_str(), "pd%d", &k)) {
                    pr3ser(-1, pd_x, "sscanf could find match");
                } else
                    de.pd_inum_ = k;
                if (de.partner_)
                    ucsi_psup_possible = true;
                else {
                    ec = get_value(itr->path(), "power_role", attr);
                    if (ec) {
                        pr3ser(-1, itr->path(), "returned by get_value()",
                               ec);
                    } else
                        print_err(3, "{}: {}: power_role: {:s}\n",
                                  __func__, filename_as_str(it_pt), attr);
                }
            }
        } else {       // not a symlink to a directory
            if (ec) {
                pr3ser(-1, itr->path(), "not symlink to directory", ec);
                continue;
            }
        }
        op->tc_de_v.push_back(de);
    }
    if (ecc)
        pr3ser(0, sc_typec_pt, "failed in iterate of scan directory", ec);
    return ecc;
}

/* Populates op->upd_de_m[pd_number] {map of int (pd number) to 'struct
 * Upd_dir_elem' objects} with information from class/usb_power_delivery/.
 * Users of that map will need this function called first (but
 * scan_for_typec_obj() should still be called before this function). */
static std::error_code
build_upd_map(struct Opts_t * op) noexcept
{
    bool want_ucc = op->do_data_dir; // unreliable USB Communications Capable
    std::error_code ec { };
    std::error_code ecc { };

    for (fs::directory_iterator itr(sc_upd_pt, dir_opt, ecc);
         (! ecc) && itr != end_itr;
         itr.increment(ecc) ) {
        const fs::path & pt { itr->path() };
        int k;

        if (itr->is_directory(ec)) {
            if (1 != sscanf(pt.filename().c_str(), "pd%d", &k))
                pr2ser(-1, "unable to find 'pd<num>' to decode");
            else {
                Upd_dir_elem ue(*itr, pd_is_partner(k, op));

                if (want_ucc && ue.is_partner_) {
                    Sstring attr;

                    ec = get_value(*itr, src_ucc_s, attr);
                    if (ec)
                        pr3ser(2, itr->path(), "<< failed get src_ucc", ec);
                    else {
                        unsigned int u;

                        if (1 == sscanf(attr.c_str(), "%u", &u)) {
                            if (u == 0)
                                ue.usb_comms_incapable_ = true;
                        }
                    }
                }
                ue.match_str_.assign(Sstring("pd") + std::to_string(k));
                op->upd_de_m.emplace(std::make_pair(k, ue));
            }
        } else if (ec)
            pr3ser(-1, pt, "failed in is_directory()", ec);
    }
    if (ecc)
        pr3ser(-1, sc_upd_pt, "was scanning when failed", ecc);
    return ecc;
}

// This JSON output can viewed as an internal (structure) object tree.
static void
do_lsucpd_internal(struct Opts_t * op, sgj_opaque_p jop) noexcept
{
    sgj_state * jsp { &op->json_st };
    sgj_opaque_p jo2p { };
    sgj_opaque_p jap { };

    jap = sgj_named_subarray_r(jsp, jop, "typec_dir_elem_list");
    for (const auto& elem : op->tc_de_v) {
        const int pd_num { elem.pd_inum_ };

        jo2p = sgj_new_unattached_object_r(jsp);
        sgj_js_nv_s(jsp, jo2p, "directory", elem.path().c_str());
        sgj_js_nv_i(jsp, jo2p, "partner", elem.partner_);
        sgj_js_nv_i(jsp, jo2p, "upd_dir_exists", elem.upd_dir_exists_);
        sgj_js_nv_i(jsp, jo2p, "source_sink_known", elem.source_sink_known_);
        sgj_js_nv_i(jsp, jo2p, "is_source", elem.is_source_);
        sgj_js_nv_i(jsp, jo2p, "data_role_known", elem.data_role_known_);
        sgj_js_nv_i(jsp, jo2p, "is_host", elem.is_host_);
        sgj_js_nv_i(jsp, jo2p, "pow_op_mode", (unsigned int)elem.pow_op_mode_);
        sgj_js_nv_i(jsp, jo2p, "port_num", elem.port_num_);
        sgj_js_nv_i(jsp, jo2p, "pd_inum", pd_num);
        sgj_js_nv_i(jsp, jo2p, "partner_ind", elem.partner_ind_);
        sgj_js_nv_s(jsp, jo2p, "match_str", elem.match_str_.c_str());
        if (elem.tc_usb_dev_v.size() > 0) {
            auto ja2p = sgj_named_subarray_r(jsp, jo2p, "usb_device_list");

            for (const auto& pt : elem.tc_usb_dev_v) {
                auto jo3p = sgj_new_unattached_object_r(jsp);

                sgj_js_nv_s(jsp, jo3p, "directory", pt.c_str());
                sgj_js_nv_s(jsp, jo3p, "bus_port",
                            filename_as_str(pt).c_str());
                sgj_js_nv_o(jsp, ja2p, nullptr, jo3p);
            }
        }
        sgj_js_nv_o(jsp, jap, nullptr, jo2p);
    }
}

// want mapping from PDO's [{B31..B30} * 2 + (obj_pos==1)] to index in
// pdo_part_a[]. Special case for PPS and AVS which are last 2 entries.
static const uint8_t pdo_part_map[] = {9, 0, 13, 13, 17, 17, 21,
                                       26 /* AVS */};

// want mapping from RDO's object type; {f+v}:0, {b}:1, {pps}:2, {avs}:3
// to index in pdo_part_a[].
static const uint8_t rdo_part_map[] = {30, 40, 50, 58};

static void
pdo2str(uint32_t a_pdo, bool ind1, bool is_src, Sstring & out) noexcept
{
    bool fl_cont { false };
    uint8_t k, num_b_typ, nb;
    uint8_t pp_map_ind = ((a_pdo >> 30) << 1);
    uint32_t l_pdo, mask;
    if (ind1)
        pp_map_ind |= 1;
    const struct Do_fld_desc_t * do_fld_p =
                         pdo_part_a + pdo_part_map[pp_map_ind];

    k = static_cast<uint8_t>(a_pdo >> 30);
    switch (k) {
    case 0:
        out = "Fixed";
        break;
    case 1:
        out = "Battery";
        break;
    case 2:
        out = "Variable";
        break;
    case 3:
        pp_map_ind = 6;
        if (0x10000000 & a_pdo) {
            do_fld_p = pdo_part_a + pdo_part_map[pp_map_ind + 1];
            out = "Adjustable voltage";
        } else {
            do_fld_p = pdo_part_a + pdo_part_map[pp_map_ind];
            out = "Programmable power";
        }
        break;
    }
    out += " supply PDO for ";
    out += is_src ? "source" : "sink";
    out += ind1 ? ", object index 1:\n" : ":\n";

    for (k = 0; true; ++k, ++do_fld_p) {
        num_b_typ = do_fld_p->num_bits_typ;
        if (0 == num_b_typ)
            break;
        if (! fl_cont) {
            if ((k > 0) && (num_b_typ & P_IT_FL_START))
                break;
        }
        fl_cont = !!(P_IT_FL_CONT & num_b_typ);
        if ((P_IT_FL_SRC & num_b_typ) && (! is_src))
            continue;
        if ((P_IT_FL_SINK & num_b_typ) && is_src)
            continue;
        if (do_fld_p->low_pdo_bit > 0)
            l_pdo = a_pdo >> do_fld_p->low_pdo_bit;
        else
            l_pdo = a_pdo;
        nb = num_b_typ & 0xf;
        mask = (1 << nb) - 1;
        l_pdo &= mask;
        out += Sstring("  ") + Sstring(pdo_str[do_fld_p->nam_str_off]);
        uint8_t mult = do_fld_p->mult;
        uint16_t l_pdo16 = (uint16_t)l_pdo;
        if (mult) {
            Arr_of_ch<16> bb { };

            l_pdo16 *= mult;
            snprintf(bb.d(), bb.sz(), "=%u.%02u\n",
                     l_pdo16 / 100, l_pdo16 % 100);
            out += Sstring(bb.d());
        } else
            out += Sstring("=") + std::to_string(l_pdo16) + Sstring("\n");
    }
}

static int
do_pdo_opt(Sstring & o_str, struct Opts_t * op) noexcept
{
    int64_t n = sg_get_llnum(op->pdo_opt_p);
    const char * snk_src_s = op->is_pdo_snk ? "snk" : "src";

    if (n < 0) {
        print_err(-1, "bad argument to --pdo-{}, decimal is the default\n",
                  snk_src_s);
        return 1;
    } else if (n > UINT32_MAX) {
        print_err(-1, "argument to --pdo-{}= does fit in 32 bits\n",
                  snk_src_s);
        return 1;
    }
    int k = 0;
    if (const char * ccp = strchr(op->pdo_opt_p, ',')) {
        k = sg_get_num(ccp + 1);
        if (k < 0) {
            print_err(-1, "bad numeric index to --pdo-{}=<si_pdo>,IND\n",
                      snk_src_s);
            return 1;
        }
    }
    pdo2str((uint32_t)n, 1 == k, ! op->is_pdo_snk, o_str);
    return 0;
}

/* RDOs are always sent by the sink to the source */
static void
rdo2str(uint32_t a_rdo, Pdo_e ref_pdo, Sstring & out) noexcept
{
    bool fl_cont { false };
    bool check_giveback { false };
    uint8_t k, num_b_typ, nb;
    uint16_t ind;
    uint32_t l_rdo, mask;

    switch (ref_pdo) {
    case Pdo_e::pdo_fixed:
        ind = rdo_part_map[0];
        check_giveback = true;
        break;
    case Pdo_e::pdo_battery:
        ind = rdo_part_map[1];
        check_giveback = true;
        break;
    case Pdo_e::pdo_variable:
        ind = rdo_part_map[0]; // Fixed and Variable RDOs have same structure
        check_giveback = true;
        break;
    case Pdo_e::apdo_pps:
        ind = rdo_part_map[2];
        break;
    case Pdo_e::apdo_epr_avs:
        ind = rdo_part_map[3];
        break;
    case Pdo_e::apdo_spr_avs:
        ind = rdo_part_map[3];  // PD r3.2 v1.0 table 6.16 needs correction
        break;
    default:
        out = "RDO refers to bad PDO type\n";
        return;
    }
    out = Sstring("RDO for ") + pdo_e_to_str(ref_pdo) + "\n";
    const struct Do_fld_desc_t * do_fld_p = pdo_part_a + ind;

    for (k = 0; true; ++k, ++do_fld_p) {
        num_b_typ = do_fld_p->num_bits_typ;
        if (0 == num_b_typ)
            break;
        if (! fl_cont) {
            if ((k > 0) && (num_b_typ & P_IT_FL_START))
                break;
        }
        fl_cont = !!(P_IT_FL_CONT & num_b_typ);
        if (check_giveback) {
            bool report_giveback = !! (0x08000000 & a_rdo);
            if ((P_IT_FL_SRC & num_b_typ) && (! report_giveback))
                continue;
            if ((P_IT_FL_SINK & num_b_typ) && report_giveback)
                continue;
        }
        if (do_fld_p->low_pdo_bit > 0)
            l_rdo = a_rdo >> do_fld_p->low_pdo_bit;
        else
            l_rdo = a_rdo;
        nb = num_b_typ & 0xf;
        mask = (1 << nb) - 1;
        l_rdo &= mask;
        out += Sstring("  ") + Sstring(pdo_str[do_fld_p->nam_str_off]);
        uint8_t mult = do_fld_p->mult;
        uint16_t l_rdo16 = (uint16_t)l_rdo;
        if (mult) {
            Arr_of_ch<16> bb { };

            if (0xff == mult) {
                // special case for AVS, bottom 2 lsb_s of voltage always 0
                // mult should be 2.5 but is an integer, improvise ...
                l_rdo16 = (l_rdo16 >> 1) * 25;
            } else
                l_rdo16 *= mult;
            snprintf(bb.d(), bb.sz(), "=%u.%02u\n",
                     l_rdo16 / 100, l_rdo16 % 100);
            out += Sstring(bb.d());
        } else
            out += Sstring("=") + std::to_string(l_rdo16) + Sstring("\n");
    }
}

static int
do_rdo_opt(Sstring & o_str, struct Opts_t * op) noexcept
{
    int64_t n = sg_get_llnum(op->rdo_opt_p);

    if (n < 0) {
        print_err(-1, "bad argument to --rdo=, decimal is the default\n");
        return 1;
    } else if (n > UINT32_MAX) {
        print_err(-1, "argument to --rdo=RDO does fit in 32 bits\n");
        return 1;
    }
    Pdo_e ref_pdo { };
    if (const char * ccp = strchr(op->rdo_opt_p, ',')) {
        switch (toupper(*(ccp + 1))) {
        case 'F':
            ref_pdo = Pdo_e::pdo_fixed;
            break;
        case 'B':
            ref_pdo = Pdo_e::pdo_battery;
            break;
        case 'V':
            ref_pdo = Pdo_e::pdo_variable;
            break;
        case 'P':
            ref_pdo = Pdo_e::apdo_pps;
            break;
        case 'A':
        case 'E':
            ref_pdo = Pdo_e::apdo_epr_avs;
            break;
        case 'S':
            ref_pdo = Pdo_e::apdo_spr_avs;
            break;
        default:
            print_err(-1, "--rdo=<rdo>,REF expects F, B, V, P, A, E or S\n");
            return 1;
        }
    } else {
        print_err(-1, "--rdo= takes two arguments: RDO and REF separated by "
                  "a comma, no spaces\n");
        return 1;
    }
    rdo2str((uint32_t)n, ref_pdo, o_str);
    return 0;
}

/* Looks frightening but because this function appends to spw_a and that
 * is a "class template with a non-type template parameter (NTTP)" then
 * this function needs a "constant template parameter" of N . Of all the
 * USB parameters available, this function chooses those most related
 * to USB-C such as speed and lanes used. The other limit is what fits
 * comfortably on a single line. */
template <std::size_t N>
static std::error_code
usb_dev_get_values(const Sstring & pt, const Sstring & match_str,
                   const Sstring & pad, SafePrintfWrapper<N> & spw_a)
{
    Sstring idVendor, idProd, speed, tlanes, rlanes, prod;
    std::error_code ec { };
    const auto & fn { filename_as_str(pt) };

    std::error_code ecc = get_value(pt, "idVendor", idVendor);
    if (ecc) {
        pr3ser(2, pt + "/idVendor", "get_value() failed", ecc);
        ec = ecc;
    }
    ecc = get_value(pt, "idProduct", idProd);
    if (ecc && ! ec)
        ec = ecc;
    if (match_str.empty())
        spw_a.scnpr("\n%s %s  %s:%s", pad.c_str(), fn.c_str(),
                    idVendor.c_str(), idProd.c_str());
    else
        spw_a.scnpr("\n%s%s: %s  %s:%s", pad.c_str(), match_str.c_str(),
                    fn.c_str(), idVendor.c_str(), idProd.c_str());
    ecc = get_value(pt, "speed", speed);
    if (ecc && ! ec)
        ec = ecc;
    ecc = get_value(pt, "tx_lanes", tlanes);
    if (ecc && ! ec)
        ec = ecc;
    ecc = get_value(pt, "rx_lanes", rlanes);
    if (ecc && ! ec)
        ec = ecc;
    spw_a.scnpr("  speed,tx/rx_lanes=%s,%s/%s", speed.c_str(),
                tlanes.c_str(), rlanes.c_str());
    ecc = get_value(pt, "product", prod);
    if (ecc && ! ec)
        ec = ecc;
    spw_a.scnpr("  %.20s", prod.c_str());
    return ec;
}

/* Loops over all USB devices found in a single Type C directory element
 * and appends a single line onto spw_a for each USB device found. See
 * usb_dev_get_values() description for why a template function is needed. */
template <std::size_t N>
static void
usb_dev_list(struct Tc_dir_elem * elemp, SafePrintfWrapper<N> & spw_a,
             struct Opts_t * op) noexcept
{
    std::error_code ecc { };

    for (size_t m = 0; m < elemp->tc_usb_dev_v.size(); ++m) {
        Sstring pt = elemp->tc_usb_dev_v[m];

        ecc = usb_dev_get_values(pt, elemp->match_str_, "    ", spw_a);
        if (ecc)
            pr3ser(1, pt, "usb_dev_get_value() failed", ecc);

        if (spw_a.full())
            break;
        if (op->do_usb_devs > 1) {
            Svector devs_2lev_v;

            ecc = scan_for_usb_devs(pt, "+([0-9])-+([0-9]).+([0-9])*",
                                    devs_2lev_v);
            if (ecc)
                pr3ser(1, pt, "scan_for_usb_devs() failed", ecc);
            if (devs_2lev_v.size() > 0) {
                Sstring ppad { "          " };

                for (const auto & l2pt : devs_2lev_v) {
                    ecc = usb_dev_get_values(l2pt, "", ppad, spw_a);
                    if (ecc)
                        pr3ser(2, pt, "inner usb_dev_get_value() failed",
                               ecc);
                }
            }
        }
    }
    if (spw_a.full())
        pr3ser(-1, elemp->match_str_, "char array full", ecc);
}

/* Sorts op->tc_de_v[0..n-1] {vector of 'struct Tc_dir_elem' objects} in
 * ascending order so that port<m>-partner entry will appear immediately
 * after the port<m>. Build a summary map [port_num->summary_string]. */
static int
primary_scan(bool ucsi_psup_possible, struct Opts_t * op) noexcept
{
    size_t sz { op->tc_de_v.size() };
    Tc_dir_elem * elemp { };
    const char * non_pd_s = nullptr;
    SafePrintfWrapper<600> spw_a;

    if (sz > 1) {
        std::ranges::sort(op->tc_de_v);
        // assume, for example, "port3" precedes "port3-partner" after sort
        // sort order example using match string: p0, p0p, p1, p2, p2p

        Tc_dir_elem * prev_elemp = nullptr;
        Arr_of_ch<32> cc;

// xxxxxxxxxxx  Testing: turn on (was 0)
#if 0
        if (ucsi_psup_possible) {
            std::error_code ecc { };

            for (fs::directory_iterator itr(sc_powsup_pt, dir_opt, ecc);
                 (! ecc) && itr != end_itr;
                 itr.increment(ecc) ) {
                const fs::path & pt { itr->path() };
                const Sstring & name { pt.filename() };
// xxxxxxxxxxx  missing code for power_supply object; don't know which one.
// xxxxxxxxxxx  Would like symlink from pd object to corresponding
// xxxxxxxxxxx  power_supply. Also having the active RDO (in hex ?) would
// xxxxxxxxxxx  be extremely useful.
pr2serr("%s: pt: %s\n", __func__, filename_as_str(pt).c_str());
            }
            if (ecc)
                pr3ser(-1, sc_powsup_pt, "was scanning when failed", ecc);
        }
#else
        if (ucsi_psup_possible) {
            ;   /* keep compiler quiet */
        }
#endif

        // associate ports (and possible partners) with pd objects.
        // Note that with regard to output of this utility, in the typical
        // case, to get one line of output, two iterations around this loop
        // are required. For example, one for port3, the next one for
        //  port3-partner, outputting: "port3 [pd3]  <<====  partner [pd5]"
        for (size_t k = 0; k < sz; ++k, prev_elemp = elemp) {
            int j;

            elemp = &op->tc_de_v[k];
            j = elemp->pd_inum_;
            if (elemp->partner_) {
                if (k > 0) {
                    bool ddir = op->do_data_dir;
                    prev_elemp->partner_ind_ = k;
                    elemp->partner_ind_ = k - 1;
                    elemp->source_sink_known_ = prev_elemp->source_sink_known_;
                    if (prev_elemp->source_sink_known_)
                        elemp->is_source_ = ! prev_elemp->is_source_;
                    elemp->data_role_known_ = prev_elemp->data_role_known_;
                    if (elemp->data_role_known_)
                        elemp->is_host_ = ! prev_elemp->is_host_;
                    if (ddir && elemp->is_source_) {
                        const auto it { op->upd_de_m.find(j) };
                        if ((it != op->upd_de_m.end()) &&
                            it->second.usb_comms_incapable_)
                            ddir = false;
                    }
                    non_pd_s = process_pw_d_dir_mode(prev_elemp, true,
                                                     cc.sz(), cc.d(), ddir);
                    spw_a.scnpr("%s partner ", cc.d());
                    if (j > 0) {        // PDO of 0x0000 is place holder
                        spw_a.scnpr("[pd%d] ", j);
                    }
                    if (non_pd_s)
                        spw_a.scnpr("%s ", non_pd_s);
                    if (elemp->tc_usb_dev_v.size() > 0) {
                        usb_dev_list(elemp, spw_a, op);
                    }
                    op->summ_out_m.emplace(
                        std::make_pair(prev_elemp->port_num_, spw_a.cz()));
                } else {
                    // don't expect partner as first element (k == 0)
                    op->summ_out_m.emplace(
                        std::make_pair(elemp->port_num_, "logic_err"));
                }
            } else {    /* local (machine's) typec port */
                if (prev_elemp && (spw_a.index() > 0)) {
                    non_pd_s = process_pw_d_dir_mode(prev_elemp, false,
                                                     cc.sz(), cc.d(),
                                                     op->do_data_dir);
                    spw_a.scnpr("%s", cc.d());
                    if (non_pd_s)
                        spw_a.scnpr(" %s", non_pd_s);
                    op->summ_out_m.emplace(
                        std::make_pair(prev_elemp->port_num_, spw_a.cz()));
                }
                spw_a.scnpr(" port%d ", elemp->port_num_);
                if (j >= 0) {
                    spw_a.scnpr("[pd%d] ", j);
                }
            }
        }       // <<<<<<<<<<<  end of long classic for loop

        // above loop needs potential cleanup on exit and that follows
        if (prev_elemp && (spw_a.index() > 0)) {
            non_pd_s = process_pw_d_dir_mode(prev_elemp, false, cc.sz(),
                                             cc.d(), op->do_data_dir);
            spw_a.scnpr("%s", cc.d());
            if (non_pd_s)
                spw_a.scnpr(" %s", non_pd_s);
            op->summ_out_m.emplace(std::make_pair(prev_elemp->port_num_,
                                   spw_a.cz()));
        }
    } else if (sz == 1) {
        Arr_of_ch<32> cc { };

        elemp = &op->tc_de_v[0];
        int j = elemp->pd_inum_;

        spw_a.scnpr(" port%d ", elemp->port_num_);
        if (j >= 0) {
             spw_a.scnpr("[pd%d] ", j);
        }
        non_pd_s = process_pw_d_dir_mode(elemp, false, cc.sz(), cc.d(),
                                         op->do_data_dir);
        spw_a.scnpr("%s", cc.d());
        if (non_pd_s)
            spw_a.scnpr(" %s", non_pd_s);
        op->summ_out_m.emplace(std::make_pair(elemp->port_num_, spw_a.cz()));
    }
    return 0;
}

static void
do_filter(struct Opts_t * op, sgj_opaque_p jop) noexcept
{
    int res;
    int a_match = false;
    std::error_code ec { };
    sgj_state * jsp { &op->json_st };
    sgj_opaque_p jo2p { };
    sgj_opaque_p jo3p { };
    sgj_opaque_p jo4p { };
    sgj_opaque_p jap { };

    for (const auto & filt : op->filter_v) {
        if (jsp->pr_as_json) {
            jo2p = sgj_named_subobject_r(jsp, jop, ct_sn);
            jap = sgj_named_subarray_r(jsp, jo2p, "typec_list");
        }
        for (const auto& entry : op->tc_de_v) {
            res = fnmatch(filt.c_str(), entry.match_str_.c_str(),
                          FNM_EXTMATCH);
            if (0 == res) {
                const unsigned int port_num = entry.port_num_;
                if (port_num == UINT32_MAX) {
                    print_err(0, "uninitialized port number for {}\n",
                              entry.match_str_);
                    continue;
                }
                a_match = true;
                sgj_hr_pri(jsp, "{}\n", op->summ_out_m[port_num]);
                if (op->do_long > 0) {
                    jo3p = sgj_new_unattached_object_r(jsp);
                    Sstring s { "port" + std::to_string(port_num) };
                    if (entry.partner_)
                        s += "_partner";
                    jo4p = sgj_named_subobject_r(jsp, jo3p,
                                                 s.c_str());
                    list_port(entry, op, jo4p);
                    sgj_js_nv_o(jsp, jap, nullptr, jo3p);
                }
            } else if (res != FNM_NOMATCH) {
                print_err(-1, "{}: failed in fnmatch(), string: {}",
                          __func__, filename_as_str(entry.match_str_));
                break;
            }
        }
    }

    if (a_match)
        sgj_hr_pri(jsp, "\n");
    if (jsp->pr_as_json) {
        jo2p = sgj_named_subobject_r(jsp, jop, cupd_sn);
        jap = sgj_named_subarray_r(jsp, jo2p, "pdo_list");
    }
    for (const auto& filt : op->filter_v) {
        for (auto&& [nm, upd_d_el] : op->upd_de_m) {
            res = fnmatch(filt.c_str(), upd_d_el.match_str_.c_str(),
                          FNM_EXTMATCH);
            if (0 == res) {
                ec = populate_src_snk_pdos(upd_d_el, op);
                if (ec) {
                    pr3ser(-1, upd_d_el.path(), "from "
                           "populate_src_snk_pdos", ec);
                    break;
                }
                jo3p = sgj_new_unattached_object_r(jsp);
                Sstring s { "pd" + std::to_string(nm) };
                jo4p = sgj_named_subobject_r(jsp, jo3p, s.c_str());
                list_pd(nm, upd_d_el, op, jo4p);
                // Sstring s { "pd" + std::to_string(nm) };
// pr2serr("%s: sgj_js_nv_o(jsp, jap, s.c_str()\n", __func__);
                sgj_js_nv_o(jsp, jap, nullptr, jo3p);
            } else if (res != FNM_NOMATCH) {
                print_err(-1, "{}: failed in fnmatch(), string: {}",
                          __func__, filename_as_str(upd_d_el.match_str_));
                break;
            }
        }
    }
    op->caps_given = false;     // would be repeated otherwise
}

/* Handles short options after '-j' including a sequence of short options
 * that include one 'j' (for JSON). Want optional argument to '-j' to be
 * prefixed by '='. Return 0 for good, 1 for syntax error
 * and 2 for exit with no error. */
static int
chk_short_opts(const char sopt_ch, struct Opts_t * op) noexcept
{
    /* only need to process short, non-argument options */
    switch (sopt_ch) {
    case 'c':
        ++op->do_caps;
        op->caps_given = true;
        break;
    case 'd':
        op->do_data_dir = true;
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
    case 'u':
        ++op->do_usb_devs;
        break;
    case 'v':
        op->verbose_given = true;
        ++lsucpd_verbose;
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

static int
cl_parse(struct Opts_t * op, int argc, char * argv[])
{
    constexpr int N = 128;
    Arr_of_ch<N> bb { };

    while (1) {
        int option_index = 0;

        int c = getopt_long(argc, argv, "^cdhj::J:lp:P:r:uvVy:", long_options,
                            &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'c':
            ++op->do_caps;
            op->caps_given = true;
            break;
        case 'd':
            op->do_data_dir = true;
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
        case 'p':
            op->pdo_opt_p = optarg;
            op->is_pdo_snk = true;
            break;
        case 'P':
            op->pdo_opt_p = optarg;
            op->is_pdo_snk = false;
            break;
        case 'r':
            op->rdo_opt_p = optarg;
            break;
        case 'u':
            ++op->do_usb_devs;
            break;
        case 'v':
            op->verbose_given = true;
            ++lsucpd_verbose;
            break;
        case 'V':
            op->version_given = true;
            break;
        case 'y':
            op->pseudo_mount_point = optarg;
            break;
        default:
            print_err(-1, "unrecognised option code: {:c} [0x{:x}]\n", c, c);
            usage();
            return 1;
        }
    }
    while (optind < argc) {
        const char * oip = argv[optind];
        auto ln = strlen(oip);
        size_t k { };

        if ((ln < 2) || (ln >= 31)) {
            print_err(-1, "expect argument of the form: 'p<num>', "
                      "'p<num>[p]' or 'pd<num>', got: {}\n", oip);
            return 1;
        }
        for (/* k = 0 */; k < ln; ++k)
            bb[k] = tolower(oip[k]);
        bb[k] = '\0';

        char c = bb[1];
        op->filter_for_pd = (c == 'd' || c == '*' || c == '?');
        if (0 == memcmp(bb.d(), "port", 4))
            memmove(bb.d() + 1, bb.d() + 4, ln - 3);
        char * cp = strstr(bb.d(), "-partner");
        if (cp)
            memcpy(cp, "p", 2);
        // bw::print("arg: {}\n", bb.d());
        op->filter_v.push_back(bb.d());
        ++optind;
    }
    return 0;
}


int
main(int argc, char * argv[])
{
    bool ucsi_psup_possible { false };
    int res { };
    std::error_code ec { };
    std::error_code ecc { };
    struct Opts_t opts { };
    struct Opts_t * op = &opts;
    sgj_state * jsp;
    sgj_opaque_p jop { };
    sgj_opaque_p jo2p { };
    sgj_opaque_p jo3p { };
    sgj_opaque_p jo4p { };
    sgj_opaque_p jap { };

    res = cl_parse(op, argc, argv);
    if (res)
        return res;
    if (op->do_help > 0) {
        usage();
        return 0;
    }
#ifdef DEBUG
    if (! op->do_json)
        pr2serr("In DEBUG mode, ");
    if (op->verbose_given && op->version_given) {
        if (! op->do_json)
            pr2serr("but override: '-vV' given, zero verbose and continue\n");
        /* op->verbose_given = false; */
        op->version_given = false;
        lsucpd_verbose = 0;
    } else if (! op->verbose_given) {
        if (! op->do_json)
            pr2serr("set '-vv'\n");
        lsucpd_verbose = 2;
    } else if (! op->do_json)
        pr2serr("keep verbose=%d\n", lsucpd_verbose);
#else
    if (op->verbose_given && op->version_given && (! op->do_json))
        pr2serr("Not in DEBUG mode, so '-vV' has no special action\n");
#endif
    if (op->version_given) {
        bw::print("{}\n", version_str);
        return 0;
    }
    if (op->pdo_opt_p) {
        Sstring ss;

        if (do_pdo_opt(ss, op))
            return 1;
        bw::print("{}", ss);
        if (nullptr == op->rdo_opt_p)
            return 0;
    }
    if (op->rdo_opt_p) {
        Sstring ss;

        res = do_rdo_opt(ss, op);
        bw::print("{}", ss);
        return res;
    }
    if (op->filter_for_pd)
        ++op->do_caps;     // pd<n> holds caps
    if (op->do_data_dir) {
        if (op->do_caps == 0)
            ++op->do_caps;     // look for usb_communication_capable setting
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
        // sgj_js_nv_s(jsp, jop, "utility_state", "under development");
    }
    if (op->pseudo_mount_point) {
        const fs::path & pt { op->pseudo_mount_point };

        if (! fs::exists(pt, ec)) {
            if (ec)
                pr3ser(-1, pt, "fs::exists error", ec);
            else
                pr3ser(-1, pt, "does not exist");
            return 1;
        } else if (! fs::is_directory(pt, ec)) {
            if (ec)
                pr3ser(-1, pt, "fs::is_directory error", ec);
            else
                pr3ser(-1, pt, "is not a directory");
            return 1;
        } else
            sysfs_root = pt;
    }
    sc_pt = fs::path(sysfs_root) / class_s;
    sc_typec_pt = sc_pt / typec_s;  // default case: /sys/class/typec
    sc_upd_pt = sc_pt / upd_sn;     // default: /sys/class/usb_power_delivery
    sc_powsup_pt = sc_pt / powsup_sn; // default: /sys/class/power_supply

    ec = scan_for_typec_obj(ucsi_psup_possible, op);
    if (ec)
        return 1;
    if ((op->do_caps > 0) || op->filter_for_pd) {
        op->build_upd_map_called = true;
        ec = build_upd_map(op);
        if (ec)
            return 1;
    }
    res = primary_scan(ucsi_psup_possible, op);
    if (res)
        return res;

    if (jsp->pr_as_json) {
        jo2p = sgj_named_subobject_r(jsp, jop, lsucpd_internal_sn);
        do_lsucpd_internal(op, jo2p);
    }

    if (op->filter_v.size() > 0) {
        do_filter(op, jop);
    } else {       // no FILTER argument given
        for (auto&& [n, v] : op->summ_out_m) {
            if (lsucpd_verbose > 4)
                sgj_hr_pri(jsp, "port={}: ", n);
            sgj_hr_pri(jsp, "{}\n", v);
        }
        if (op->do_long > 0) {
            sgj_hr_pri(jsp, "\n");
            if (jsp->pr_as_json) {
                jo2p = sgj_named_subobject_r(jsp, jop, ct_sn);
                jap = sgj_named_subarray_r(jsp, jo2p, "typec_list");
            }
            for (auto&& [n, v] : op->summ_out_m) {
                for (const auto& entry : op->tc_de_v) {
                    if (n == entry.port_num_) {
                        jo3p = sgj_new_unattached_object_r(jsp);
                        Sstring s { "port" + std::to_string(n) };
                        if (entry.partner_)
                            s += "_partner";
                        jo4p = sgj_named_subobject_r(jsp, jo3p, s.c_str());
                        list_port(entry, op, jo4p);
                        sgj_js_nv_o(jsp, jap, nullptr, jo3p);
                    }
                }
            }
        }
    }

    if (op->caps_given) {
        sgj_hr_pri(jsp, "\n");

        if (jsp->pr_as_json) {
            jo2p = sgj_named_subobject_r(jsp, jop, cupd_sn);
            jap = sgj_named_subarray_r(jsp, jo2p, "pdo_list");
        }
        for (auto&& [nm, upd_d_el] : op->upd_de_m) {
            print_err(3, "nm={}, about to populate on: {}\n", nm,
                      upd_d_el.match_str_);
            ec = populate_src_snk_pdos(upd_d_el, op);
            if (ec) {
                pr3ser(-1, upd_d_el.path(), "from populate_src_snk_pdos", ec);
                break;
            }
            jo3p = sgj_new_unattached_object_r(jsp);
            list_pd(nm, upd_d_el, op, jo3p);
            sgj_js_nv_o(jsp, jap, nullptr /* name */, jo3p);
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
