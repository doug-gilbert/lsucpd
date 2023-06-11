/*
 * Copyright (c) 2014-2023 Douglas Gilbert.
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

static const char * const version_str = "0.90 20230611";

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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif



namespace fs = std::filesystem;
using sstring=std::string;

static const struct option long_options[] = {
    // {"count", required_argument, 0, 'C'},
    {"help", no_argument, 0, 'h'},
    {"verbose", no_argument, 0, 'v'},
    {"version", no_argument, 0, 'V'},
    {0, 0, 0, 0},
};

static const char * const upd_sn = "usb_power_delivery";
static const char * const typec_s = "typec";
static const char * const sclass_sn = "/sys/class";

static const fs::path sc_pt { sclass_sn };
static const fs::path sc_typec_pt { sc_pt / typec_s };
static const fs::path sc_upd_pt { sc_pt / upd_sn };


struct dir_elem : public fs::directory_entry {
    dir_elem(const fs::directory_entry & bs) : fs::directory_entry(bs) { };

    bool is_partner() const { return partner_; }

    bool partner_ {false};

    bool upd_dir_exists_ {false};

    int pd_inum_ {-1};
};


#if 0
void demo(const fs::path& pth, fs::file_status s = fs::file_status{})
{

    std::cout << pth;
    if(fs::status_known(s) ? fs::exists(s) : fs::exists(pth))
        std::cout << " Found\n";
    else
        std::cout << "Not Found\n";
}
#endif

/* Return of 0 is good, else it is errno of failure */
static int
get_value(const fs::path & dir, const sstring & base_name,
          int max_value_len, sstring & val_out)
{
    int len;
    FILE * f;
    fs::path vnm { dir / base_name };
    char * bp;

std::cout << __func__ << ": vnm: " << vnm << "\n";
    val_out.clear();
    val_out.resize(max_value_len);
    bp = val_out.data();
    if (NULL == (f = fopen(vnm.c_str(), "r"))) {
        return errno;
    }
    if (NULL == fgets(bp, max_value_len, f)) {
        /* assume empty */
        val_out.clear();
        fclose(f);
        return 1;
    }
    len = val_out.size();
    if ((len > 0) && (bp[len - 1] == '\n'))
            val_out.erase(len - 1, 1);
    fclose(f);
    return 0;
}

static void
usage()
{
}


int main(int argc, char * argv[])
{
    auto dir_opt = fs::directory_options::skip_permission_denied;
    std::error_code ec { };
    std::vector<dir_elem> tc_de_v;
    std::map<int, fs::directory_entry> upd_de_m;
    const char * device_name = NULL;
    int verbose = 0;
    int c;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "hvV", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'h':
            usage();
            return 0;
        case 'v':
            ++verbose;
            break;
        case 'V':
            std::cout << version_str << "\n";
            return 0;
        default:
            std::cerr << "unrecognised option code 0x" << c << "\n";
            usage();
            return 1;
        }
    }
    if (optind < argc) {
        if (NULL == device_name) {
            device_name = argv[optind];
            ++optind;
        }
        if (optind < argc) {
            for (; optind < argc; ++optind)
                std::cerr << "Unexpected extra argument: " << argv[optind] << "\n";
            usage();
            return 1;
        }
    }

    std::cout << sc_typec_pt << ":\n";
    for (const auto& entry : fs::directory_iterator(sc_typec_pt, dir_opt, ec)) {
        // std::cout << entry.path().filename() << "\n";
        dir_elem de(entry);
        sstring basename { entry.path().filename() };

        if (strstr(basename.c_str(), "partner")) {
            // needs C++23: if (basename.contains("partner"))
            de.partner_ = true;
        }
        if (entry.is_directory(ec) && entry.is_symlink(ec)) {
            fs::path pt { entry.path() / upd_sn };

            if (fs::exists(pt, ec)) {
                sstring attr;
                int k;

                de.upd_dir_exists_ = true;
                fs::path c_pt { fs::canonical(pt, ec) };
                if (ec) {
                    std::cerr << "Failed to canonize: " << pt << ", error: " << ec.message() << "\n";
                    return 1;
                }
                sstring pd_x { c_pt.filename() };
                if (1 != sscanf(pd_x.c_str(), "pd%d", &k)) {
                    std::cerr << "Failed to sscanf: " << pd_x << "\n";
                } else
                    de.pd_inum_ = k;
                if (! de.partner_) {
                    int res = get_value(entry.path(), "power_role", 32, attr);

                    if (0 == res) {
                        std::cout << "power_role: " << attr << "\n";
                    } else {
                        std::cerr << "Failed to get_value(), res: " << res << "\n";
                    }
                }
            }
        } else {
            if (ec) {
                std::cerr << "is_directory && is_symlink failed: " << entry << ", error: " << ec.message() << "\n";
                return 1;
            }
        }
        tc_de_v.push_back(de);
    }
    if (ec) {
        std::cerr << "Failed to scan: " << sc_typec_pt << ", error: " << ec.message() << "\n";
        return 1;
    }
    std::ranges::sort(tc_de_v);
    for (const auto& entry : tc_de_v) {
        sstring basename {entry.path().filename()};

        std::cout << "  " << basename << ",  partner=" << entry.is_partner()
                  << ",  [pd" << entry.pd_inum_ << "] :\n";
        if (entry.is_directory(ec) && entry.is_symlink(ec)) {
            const auto & slink = fs::read_symlink(entry, ec);

            if (ec) {
                std::cerr << "Failed to read_symlink: " << entry << ", error: " << ec.message() << "\n";
                return 1;
            } else
                std::cout << "    --> " << slink << "\n";

#if 1
            fs::path ppt = fs::canonical(entry.path()). parent_path();
            std::cout << "    path: " << entry << "\n";
            std::cout << "    parent c_path: " << ppt << "\n";
            std::cout << "    parent^2 c_path: " << ppt.parent_path() << "\n";
#else
            fs::current_path(entry, ec);
            if (ec) {
                std::cerr << "Failed to cd to: " << entry << ", error: " << ec.message() << "\n";
                return 1;
            } else
                std::cout << "    pwd -P: " << fs::current_path() << "\n";
#endif
        } else {
            if (ec) {
                std::cerr << "is_directory && is_symlink failed: " << entry << ", error: " << ec.message() << "\n";
                return 1;
            }
        }
    }
    std::cout << "\n\n";

    std::cout << sc_upd_pt << ":\n";
    for (const auto& entry : fs::directory_iterator(sc_upd_pt, dir_opt, ec)) {
        fs::path pt { entry.path() };
        int k;

        // std::cout << entry.path().filename() << "\n";
        if (1 != sscanf(pt.filename().c_str(), "pd%d", &k))
            std::cerr << "unable to find 'pd<num>' to decode\n";
        else
            upd_de_m[k] = entry;
    }
    if (ec) {
        std::cerr << "Failed to scan: " << sc_upd_pt << ", error: " << ec.message() << "\n";
        return 1;
    }

    for (int k = 0; auto&& [nm, val] : upd_de_m) {  /* iterating on map gives a pair */
        const sstring basename {val.path().filename()};

        std::cout << "  index=" << k << ",  " << basename << ":\n";
        // std::cout << "  " << basename << ",  partner=" << entry.is_partner() << ":\n";
        if (val.is_directory(ec) && val.is_symlink(ec)) {
            if (ec) {
                std::cerr << "is_directory && is_symlink failed: " << val << ", error: " << ec.message() << "\n";
                return 1;
            }
            const auto & slink = fs::read_symlink(val, ec);
            if (ec) {
                std::cerr << "Failed to read_symlink: " << val << ", error: " << ec.message() << "\n";
                return 1;
            } else
                std::cout << "    --> " << slink << "\n";
#if 1
            fs::path ppt = fs::canonical(val.path()). parent_path();
            std::cout << "    path: " << val << "\n";
            std::cout << "    parent c_path: " << ppt << "\n";
            std::cout << "    parent^2 c_path: " << ppt.parent_path() << "\n";
#else
            fs::current_path(val, ec);
            if (ec) {
                std::cerr << "Failed to cd to: " << val << ", error: " << ec.message() << "\n";
                return 1;
            } else
                std::cout << "    pwd -P: " << fs::current_path() << "\n";
#endif
        } else {
            if (ec) {
                std::cerr << "[2] is_directory && is_symlink failed: " << val << ", error: " << ec.message() << "\n";
                return 1;
            }
        }
        ++k;
    }
#if 0
    fs::create_directory(Filebox, ec);
    if (ec) {
        std::cerr << "Failed to create: " << Filebox << ", error: " << ec.message() << "\n";
        return 1;
    }
    std::ofstream{Filebox/"file"};
    fs::create_symlink("file", Filebox/"symlink");
     demo (Filebox);
    for (const auto& entry : fs::directory_iterator(Filebox))
        demo (entry, entry.status());
    // fs::remove_all(Filebox);
#endif
}



#if 0

#define _XOPEN_SOURCE 600
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <libgen.h>
#include <sys/sysmacros.h>
#ifndef major
#include <sys/types.h>
#endif
#include <linux/major.h>
#include <linux/limits.h>
#include <time.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sg_unaligned.h"
#include "sg_pr2serr.h"
#include "sg_json.h"

/* Package release number is first number, whole string is version */
static const char * release_str = "0.33  2023/06/08 [svn: r191]";

#define FT_OTHER 0
#define FT_BLOCK 1
#define FT_CHAR 2

/* N.B. The following are distinct from T10's PROTOCOL identifier values */
#define TRANSPORT_UNKNOWN 0
#define TRANSPORT_SPI 1
#define TRANSPORT_FC 2
#define TRANSPORT_SAS 3         /* PROTOCOL identifier for SAS is 6 */
#define TRANSPORT_SAS_CLASS 4
#define TRANSPORT_ISCSI 5
#define TRANSPORT_SBP 6
#define TRANSPORT_USB 7
#define TRANSPORT_ATA 8         /* probably PATA, could be SATA */
#define TRANSPORT_SATA 9        /* most likely SATA */
#define TRANSPORT_FCOE 10
#define TRANSPORT_SRP 11
#define TRANSPORT_PCIE 12       /* most likely NVMe */

#define NVME_HOST_NUM 0x7fff    /* 32767, high to avoid SCSI host numbers */

#ifdef PATH_MAX
#define LMAX_PATH PATH_MAX
#else
#define LMAX_PATH 2048
#endif

#ifdef NAME_MAX
#define LMAX_NAME (NAME_MAX + 1)
#else
#define LMAX_NAME 256
#endif

#define LMAX_DEVPATH (LMAX_NAME + 128)

#define UINT64_LAST ((uint64_t)~0)

#define SEP_EQ_NO_SP SGJ_SEP_EQUAL_NO_SPACE

static int transport_id = TRANSPORT_UNKNOWN;

static const char * sysfsroot = "/sys"; /* can be replaced by '-y <dir>' */

/* Almost all static, const string names end with _s or _sn (snake) in
 * order to make code a bit easier to read. Many are used repeatedly so
 * this reduces the size of the binary. */
static const char * sdev_s = "scsi_device";
static const char * bus_scsi_dev_s = "/bus/scsi/devices";
static const char * cl_s = "class";
static const char * scsi_host_s = "/class/scsi_host/";
static const char * spi_host_s = "/class/spi_host/";
static const char * sas_host_s = "/class/sas_host/";
static const char * sas_phy_s = "/class/sas_phy/";
static const char * sasdev_s = "sas_device";
static const char * fc_h_s = "fc_host";
static const char * fc_rem_pts_s = "fc_remote_ports";
static const char * iscsi_h_s = "/class/iscsi_host/";
static const char * iscsi_sess_s = "/class/iscsi_session/";
static const char * srp_h_s = "/class/srp_host/";
static const char * dev_dir_s = "/dev";
static const char * dev_disk_byid_dir = "/dev/disk/by-id";
static const char * pdt_sn = "peripheral_device_type";
static const char * mmnbl_s = "module may not be loaded";
static const char * lun_s = "lun";
static const char * nm_s = "name";
static const char * vend_s = "vendor";
static const char * vend_sn = "t10_vendor_identification";
static const char * model_s = "model";
static const char * product_sn = "product_identification";
static const char * rev_s = "rev";
static const char * revis_s = "revision";
static const char * lbs_sn = "logical_block_size";
static const char * pbs_sn = "physical_block_size";
static const char * qu_s = "queue";
static const char * sas_ad_s = "sas_address";
static const char * sas_ad2_s = "sas_addr";
static const char * dev_n_s = "device_name";
static const char * ph_id_s = "phy_identifier";
static const char * lr_s = "linkrate";
static const char * min_lr_s = "minimum_linkrate";
static const char * min_lrh_s = "minimum_linkrate_hw";
static const char * max_lr_s = "maximum_linkrate";
static const char * max_lrh_s = "maximum_linkrate_hw";
static const char * neg_lr_s = "negotiated_linkrate";
static const char * ffd_s = "fetched from directory";
static const char * trans_s = "transport";
static const char * subtrans_s = "sub_transport";
static const char * ndn_s = "node_name";
static const char * ptn_s = "port_name";
static const char * pti_s = "port_id";
static const char * pts_s = "port_state";
static const char * scl_s = "supported_classes";
static const char * odgi_s = "orig_dgid=%s\n";
static const char * dgi_s = "dgid=%s\n";
static const char * ipp_s = "initiator_port_protocols";
static const char * sti_s = "scsi_target_id";
static const char * tpp_s = "target_port_protocols";
static const char * ip_s = "iproto";
static const char * tp_s = "tproto";
static const char * tgtn_s = "targetname";
static const char * tpgt_s = "tpgt";
static const char * i1394id_s = "ieee1394_id";
static const char * wwn_s = "wwn";
static const char * nulln1_s = "<NULL>";
static const char * nulln2_s = "(null)";
static const char * dvc_s = "device";
static const char * dv_s = "dev";
static const char * lsscsi_loc_s = "lsscsi_locator";
static const char * stat_s = "state";
static const char * mbs_s = "megabytes";
static const char * gbs_s = "gigabytes";
static const char * uniqi_s = "unique_id";
static const char * pcie_s = "pcie";
static const char * none_s = "none";

#if (HAVE_NVME && (! IGNORE_NVME))
static const char * class_nvme = "/class/nvme/";
static const char * dev_node_s = "device_node";
static const char * ker_node_s = "kernel_node";
static const char * svp_s = "subsystem_vendor";
static const char * sdp_s = "subsystem_device";
static const char * ser_s = "serial";
static const char * fr_s = "firmware_rev";
static const char * cntlid_s = "cntlid";
static const char * nsid_s = "nsid";
static const char * wwid_s = "wwid";
static const char * addr_s = "address";
#endif

static char wd_at_start[LMAX_DEVPATH];

/* For SCSI 'h' is host_num, 'c' is channel, 't' is target, 'l' is LUN is
 * uint64_t and lun_arr[8] is LUN as 8 byte array. For NVMe, h=0x7fff
 * (NVME_HOST_NUM) and displayed as 'N'; 'c' is Linux's NVMe controller
 * number, 't' is NVMe Identify controller CTNLID field, and 'l' is
 * namespace id (1 to (2**32)-1) rendered as a little endian 4 byte sequence
 * in lun_arr, last 4 bytes are zeros. invalidate_hctl() puts -1 in
 * integers, 0xff in bytes */
struct addr_hctl {
        int h;                 /* if h==0x7fff, display as 'N' for NVMe */
        int c;
        int t;
        uint64_t l;           /* SCSI: Linux word flipped; NVME: uint32_t */
        uint8_t lun_arr[8];   /* T10, SAM-5 order; NVME: little endian */
};

struct addr_hctl filter;
static bool filter_active = false;

struct lsscsi_opts {
        bool brief;         /* -b */
        bool classic;       /* -c */
        bool dev_maj_min;   /* -d */
        bool generic;       /* -g */
        bool do_hosts;      /* -H or -C */
        bool do_json;       /* -j or -J */
        bool kname;         /* -k */
        bool no_nvme;       /* -N */
        bool pdt;           /* -D= peripheral device type in hex */
        bool protection;    /* -p: data integrity */
        bool protmode;      /* -P: data integrity */
        bool scsi_id;       /* -i: udev derived from /dev/disk/by-id/scsi* */
        bool scsi_id_twice; /* -ii: scsi_id without "from whence" prefix */
        bool transport_info;  /* -t */
        bool wwn;           /* -w */
        bool wwn_twice;     /* -ww */
        int long_opt;       /* -l: --long; -L equivalent to -lll */
        int lunhex;         /* -x */
        int ssize;          /* show storage size, once->base 10 (e.g. 3 GB
                             * twice ->base 2 (e.g. 3.1 GiB); thrice for
                             * number of logical blocks */
        int unit;           /* -u: logical unit (LU) name: from vpd_pg83 */
        int verbose;        /* -v */
        int version_count;  /* -V */
        const char * json_arg;  /* carries [JO] if any */
        const char * js_file; /* --js-file= argument */
        sgj_state json_st;  /* -j[JO] or --json[=JO] */
};

static int gl_verbose;


static const char * const scsi_device_types[] = {
        "Direct-Access",
        "Sequential-Access",
        "Printer",
        "Processor",
        "Write-once",
        "CD-ROM",
        "Scanner",
        "Optical memory",
        "Medium Changer",
        "Communications",
        "Unknown (0xa)",
        "Unknown (0xb)",
        "Storage array",
        "Enclosure",
        "Simplified direct-access",
        "Optical card read/writer",
        "Bridge controller",
        "Object based storage",
        "Automation Drive interface",
        "Security manager",
        "Zoned Block",
        "Reserved (0x15)", "Reserved (0x16)", "Reserved (0x17)",
        "Reserved (0x18)", "Reserved (0x19)", "Reserved (0x1a)",
        "Reserved (0x1b)", "Reserved (0x1c)", "Reserved (0x1d)",
        "Well known LU",
        "No device",
};

static const char * const scsi_short_device_types[] = {
        "disk   ", "tape   ", "printer", "process", "worm   ", "cd/dvd ",
        "scanner", "optical", "mediumx", "comms  ", "(0xa)  ", "(0xb)  ",
        "storage", "enclosu", "sim dsk", "opti rd", "bridge ", "osd    ",
        "adi    ", "sec man", "zbc    ", "(0x15) ", "(0x16) ", "(0x17) ",
        "(0x18) ", "(0x19) ", "(0x1a) ", "(0x1b) ", "(0x1c) ", "(0x1d) ",
        "wlun   ", "no dev ",
};

/* '--name' ('-n') option removed in version 0.11 and can now be reused */
static struct option long_options[] = {
        {"brief", no_argument, 0, 'b'},
        {"classic", no_argument, 0, 'c'},
        {"controllers", no_argument, 0, 'C'},
        {"device", no_argument, 0, 'd'},
        {"generic", no_argument, 0, 'g'},
        {"help", no_argument, 0, 'h'},
        {"hosts", no_argument, 0, 'H'},
        {"json", optional_argument, 0, '^'},    /* short option is '-j' */
        {"js-file", required_argument, 0, 'J'},
        {"js_file", required_argument, 0, 'J'},
        {"kname", no_argument, 0, 'k'},
        {"long", no_argument, 0, 'l'},
        {"list", no_argument, 0, 'L'},
        {"lunhex", no_argument, 0, 'x'},
        {"no-nvme", no_argument, 0, 'N'},       /* allow both '-' and '_' */
        {"no_nvme", no_argument, 0, 'N'},
        {"pdt", no_argument, 0, 'D'},
        {"protection", no_argument, 0, 'p'},
        {"protmode", no_argument, 0, 'P'},
        {"scsi_id", no_argument, 0, 'i'},
        {"scsi-id", no_argument, 0, 'i'}, /* convenience, not documented */
        {"size", no_argument, 0, 's'},
        {"sz-lbs", no_argument, 0, 'S'},
        {"sz_lbs", no_argument, 0, 'S'},  /* convenience, not documented */
        {"sysfsroot", required_argument, 0, 'y'},
        {"transport", no_argument, 0, 't'},
        {"unit", no_argument, 0, 'u'},
        {"long_unit", no_argument, 0, 'U'},
        {"long-unit", no_argument, 0, 'U'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {"wwn", no_argument, 0, 'w'},
        {0, 0, 0, 0}
};

static void tag_lun(const uint8_t * lunp, int * tag_arr);


/* Device node list: contains the information needed to match a node with a
 * sysfs class device. */
#define DEV_NODE_LIST_ENTRIES 16
enum dev_type {BLK_DEV, CHR_DEV};

struct dev_node_entry {
       unsigned int maj, min;
       enum dev_type d_typ;
       time_t mtime;
       char name[LMAX_DEVPATH];
};

struct dev_node_list {
       struct dev_node_list *next;
       unsigned int count;
       struct dev_node_entry nodes[DEV_NODE_LIST_ENTRIES];
};
static struct dev_node_list* dev_node_listhead = NULL;

/* Allow for '0x' + prefix + wwn<128-bit> + <null-terminator> */
#define DSK_WWN_MXLEN 36

struct disk_wwn_node_entry {
        char wwn[DSK_WWN_MXLEN];
        char disk_bname[12];
};

#define DISK_WWN_NODE_LIST_ENTRIES 16
struct disk_wwn_node_list {
        struct disk_wwn_node_list *next;
        unsigned int count;
        struct disk_wwn_node_entry nodes[DISK_WWN_NODE_LIST_ENTRIES];
};
static struct disk_wwn_node_list * disk_wwn_node_listhead = NULL;

struct item_t {
        char name[LMAX_DEVPATH];
        int ft;
        int d_type;
};

static struct item_t non_sg;
static struct item_t aa_sg;
static struct item_t aa_first;
static struct item_t enclosure_device;
#if (HAVE_NVME && (! IGNORE_NVME))
static struct item_t aa_ng;
#endif

static char sas_low_phy[LMAX_NAME];
static char sas_hold_end_device[LMAX_NAME];

/* A code analyzer sees a potential local auto leak via these next two
 * pointers. While the leak is there, it is not exploited. The warning
 * is circumvented by writing NULL to them on their way out of
 * iscsi_target_scan(). */
static const char * iscsi_dir_name;
static const struct addr_hctl * iscsi_target_hct;

static int iscsi_tsession_num;

static char errpath[LMAX_PATH];


static const char * const usage_message1 =
    "Usage: lsscsi  [--brief] [--classic] [--controllers] [--device] "
    "[--generic]\n"
    "               [--help] [--hosts] [--json[=JO]] [--js-file=JFN] "
    "[--kname]\n"
    "               [--list] [--long] [--long-unit] [--lunhex] [--no-nvme] "
    "[--pdt]\n"
    "               [--protection] [--prot-mode] [--scsi_id] [--size] "
    "[--sz-lbs]\n"
    "               [--sysfsroot=PATH] [--transport] [--unit] [--verbose]\n"
    "               [--version] [--wwn]  [<h:c:t:l>]\n"
    "  where:\n"
    "    --brief|-b        tuple and device name only\n"
    "    --classic|-c      alternate output similar to 'cat "
    "/proc/scsi/scsi'\n"
    "    --controllers|-C   synonym for --hosts since NVMe controllers "
    "treated\n"
    "                       like SCSI hosts\n"
    "    --device|-d       show device node's major + minor numbers\n"
    "    --generic|-g      show scsi generic device name\n"
    "    --help|-h         this usage information\n"
    "    --hosts|-H        lists scsi hosts rather than scsi devices\n"
    "    --json[=JO]|-j[=JO]    output in JSON instead of plain text. "
    "Use\n"
    "                           --json=? or '-j=?' for JSON help\n"
    "    --js-file=JFN|-J JFN    JFN is a filename to which JSON output is\n"
    "                            written (def: stdout); truncates then "
    "writes\n"
    "    --kname|-k        show kernel name instead of device node name\n"
    "    --list|-L         additional information output one\n"
    "                      attribute=value per line\n"
    "    --long|-l         additional information output\n"
    "    --long-unit|-U    print LU name in full, use twice to prefix with\n"
    "                      '.naa', 'eui.', 'uuid.' or 't10.'\n"
    "    --lunhex|-x       show LUN part of tuple as hex number in T10 "
    "format;\n";

static const char * const usage_message2 =
    "                      use twice to get full 16 digit hexadecimal LUN\n"
    "    --no-nvme|-N      exclude NVMe devices from output\n"
    "    --pdt|-D          show the peripheral device type in hex\n"
    "    --protection|-p   show target and initiator protection information\n"
    "    --protmode|-P     show negotiated protection information mode\n"
    "    --scsi_id|-i      show udev derived /dev/disk/by-id/scsi* entry\n"
    "    --size|-s         show disk size, (once for decimal (e.g. 3 GB),\n"
    "                      twice for power of two (e.g. 2.7 GiB),\n"
    "                      thrice for number of blocks))\n"
    "    --sysfsroot=PATH|-y PATH    set sysfs mount point to PATH (def: "
    "/sys)\n"
    "    --sz-lbs|-S       show size as a number of logical blocks; if used "
    "twice\n"
    "                      adds comma followed by logical block size in "
    "bytes\n"
    "    --transport|-t    transport information for target or, if "
    "'--hosts'\n"
    "                      given, for initiator\n"
    "    --unit|-u         logical unit (LU) name (aka WWN for ATA/SATA)\n"
    "    --verbose|-v      output path names where data is found\n"
    "    --version|-V      output version string and exit\n"
    "    --wwn|-w          output WWN for disks (from /dev/disk/by-id/*)\n"
    "    <h:c:t:l>         filter output list (def: '*:*:*:*' (all)). "
    "Meaning:\n"
    "                      <host_num:controller:target:lun> or for NVMe:\n"
    "                      <'N':ctl_num:cntlid:namespace_id>\n\n"
    "List SCSI devices or hosts, followed by NVMe namespaces or "
    "controllers.\nMany storage devices (e.g. SATA disks and USB attached "
    "storage) use SCSI\ncommand sets and hence are also listed by this "
    "utility. Hyphenated long\noption names can also take underscore (and "
    "vice versa).\n";


#if (HAVE_NVME && (! IGNORE_NVME))

/* trims leading whitespaces, if trim_leading is true; and trims trailing
 * whitespaces, if trim_trailing is true. Edits s in place. If s is NULL
 * or empty (or both bools are false) it does nothing. Returns length of
 * processed string (or 0 if s is NULL). */
static int
trim_lead_trail(char * s, bool trim_leading, bool trim_trailing)
{
        int n;
        char * p = s;

        if ((NULL == s) || (0 == ((n = (int)strlen(p)))) ||
            (! (trim_leading && trim_trailing))) /* sanity checks */
                return s ? (int)strlen(s) : 0;

        if (trim_trailing) {
                while (isspace((uint8_t)p[n - 1]))
                        p[--n] = 0;
        }
        if (trim_leading) {
                while (*p && isspace((uint8_t)*p)) {
                        ++p;
                        --n;
                }
                memmove(s, p, n + 1);
        }
        return (int)strlen(s);
}

/* Truncate or pad string to length n, plus adds null byte to str assumed to
 * be at least n+1 bytes long. If shorter than n, pads with spaces to right.
 * If truncated and trailing__on_trunc is true and last character (after
 * truncate) is not whitespace, then places "_" in last character position. */
static void
trunc_pad2n(char * str, int n, bool trailing__on_trunc)
{
    int slen = strlen(str);

    if (slen < n) {
        memset(str + slen, ' ', n - slen);
        str[n] = '\0';
    } else if (slen > n) {
        str[n] = '\0';
        if ((n > 0) && trailing__on_trunc && (! isspace((uint8_t)str[n - 1])))
                str[n - 1] = '_';
    }
}

static const char * bad_arg = "Bad_argument";

/* Opens the file 'dirp/fname' and searches for 'name'=, the first one found
 * has its value (rest of line after "=") returned in 'b'. The 'name' is
 * typically in upper case. Example: 'MAJOR=253' if name is 'MAJOR' returns
 * pointer to string containing '253'. */
static char *
name_eq2value(const char * dirp, const char * fname, const char * name,
              int b_len, char * b)
{
        bool ok = false;
        int k;
        size_t len = 0;
        size_t n;
        char * full_name;
        FILE * fp = NULL;
        char line[132];

        if (b_len > 0)
                b[0] = '\0';
        if (b_len < 2)
                return b;
        if (dirp)
                len = strlen(dirp);
        if (fname)
                len += strlen(fname);
        if (len < 1) {
                snprintf(b, b_len, "%s", bad_arg);
                return b;
        }
        len += 20;
        full_name = (char *)calloc(1, len);
        if (NULL == full_name)
                goto clean_up;
        if (dirp && fname)
                snprintf(full_name, len - 2, "%s/%s", dirp, fname);
        else if (dirp)
                snprintf(full_name, len - 2, "%s", dirp);
        else    /* fname must be nz (if zero(null) then len==0 above) */
                snprintf(full_name, len - 2, "%s", fname);

        fp = fopen(full_name, "r");
        if (NULL == fp)
                goto clean_up;

        if (strlen(name) >= (len - 2)) {
                snprintf(b, b_len, "%s", bad_arg);
                goto clean_up;
        }
        /* Re-use full_name as filename no longer needed */
        snprintf(full_name, len - 1, "%s=", name);
        n = strlen(full_name);

        for (k = 0; k < 1024; ++k) {    /* shouldn't be that many lines */
                if (NULL == fgets(line, sizeof(line), fp))
                        break;
                if (0 == strncmp(line, full_name, n)) {
                        ok = true;
                        break;
                }
        }
        if (ok) {
                snprintf(b, b_len, "%s", line + n);
                n = strlen(b);
                if ((n > 0) && ('\n' == b[n - 1]))
                        b[n - 1] = '\0';        /* remove trailing LF */
        }
clean_up:
        free(full_name);
        if (fp)
                fclose(fp);
        return b;
}

#endif          /* (HAVE_NVME && (! IGNORE_NVME)) */

/* Returns true if dirent entry is either a symlink or a directory
 * starting_with given name. If starting_with is NULL choose all that are
 * either symlinks or directories other than . or .. (own directory or
 * parent) . Can be tricked because symlink could point to .. (parent),
 * for example. Otherwise return false. */
static bool
dir_or_link(const struct dirent * s, const char * starting_with)
{
        if (DT_LNK == s->d_type) {
                if (starting_with)
                        return 0 == strncmp(s->d_name, starting_with,
                                            strlen(starting_with));
                return true;
        } else if (DT_DIR != s->d_type)
                return false;
        else {  /* Assume can't have zero length directory name */
                size_t len = strlen(s->d_name);

                if (starting_with)
                        return 0 == strncmp(s->d_name, starting_with,
                                            strlen(starting_with));
                if (len > 2)
                        return true;
                if ('.' == s->d_name[0]) {
                        if (1 == len)
                                return false;   /* this directory: '.' */
                        else if ('.' == s->d_name[1])
                                return false;   /* parent: '..' */
                }
                return true;
        }
}

static bool
stat_is_dir_or_symlink(struct stat * statp)
{
        return S_ISDIR(statp->st_mode) || S_ISLNK(statp->st_mode);
}

static void
usage(void)
{
        pr2serr("%s%s", usage_message1, usage_message2);
}

/* Copies (dest_maxlen - 1) or less chars from src to dest. Less chars are
 * copied if '\0' char found in src. As long as dest_maxlen > 0 then dest
 * will be '\0' terminated on exit. If dest_maxlen < 1 then does nothing. */
static void
my_strcopy(char *dest, const char *src, int dest_maxlen)
{
        const char * lp;

        if (dest_maxlen < 1)
                return;
        lp = (const char *)memchr(src, 0, dest_maxlen);
        if (NULL == lp) {
                memcpy(dest, src, dest_maxlen - 1);
                dest[dest_maxlen - 1] = '\0';
        } else
                memcpy(dest, src, (lp  - src) + 1);
}

static uint64_t
lun_word_flip(uint64_t in)
{
        int k;
        uint64_t res = 0;

        for (k = 0; ; ++k) {
                res |= (in & 0xffff);
                if (k > 2)
                        break;
                res <<= 16;
                in >>= 16;
        }
        return res;
}

/* Bits 3, 2, 1, 0 in sel_mask select the h, c, t, l components respectively.
 * Bits 4+5 of sel_mask convey the --lunhex option selecting l (LUN) in
 * hex. Generates string of the form %d:%d:%d with a colon between
 * components, returns 4th argument. */
static char *
tuple2string(const struct addr_hctl * tp, int sel_mask, int blen, char * b)
{
        bool got1 = false;
        bool is_nvme = (NVME_HOST_NUM == tp->h);
        int n = 0;

        if (0x8 & sel_mask) {
                if (is_nvme)
                        n += sg_scn3pr(b, blen, n, "N");
                else
                        n += sg_scn3pr(b, blen, n, "%d", tp->h);
                got1 = true;
        }
        if (0x4 & sel_mask) {
                n += sg_scn3pr(b, blen, n, "%s%d", got1 ? ":" : "", tp->c);
                got1 = true;
        }
        if (0x2 & sel_mask) {
                n += sg_scn3pr(b, blen, n, "%s%d", got1 ? ":" : "", tp->t);
                got1 = true;
        }
        if ((! is_nvme) && (0x1 & sel_mask)) {
                int lunhex = (sel_mask >> 4) & 0x3;

                if (1 == lunhex) {  /* -x (--lunhex) format */
                        int ta, k;
                        int tag_arr[16];

                        n += sg_scn3pr(b, blen, n, "%s0x", got1 ? ":" : "");
                        tag_lun(tp->lun_arr, tag_arr);
                        for (k = 0; k < 8; ++k) {
                                ta = tag_arr[k];
                                if (ta <= 0)
                                        break;
                                n += sg_scn3pr(b, blen, n, "%s%02x",
                                               ((ta > 1) ? "_" : ""),
                                               tp->lun_arr[k]);
                        }
                } else if (lunhex > 1) /* -xx (--lunhex twice) */
                        n += sg_scn3pr(b, blen, n, "%s0x%016" PRIx64,
                                       got1 ? ":" : "", lun_word_flip(tp->l));
                else if (UINT64_LAST == tp->l)
                        n += sg_scn3pr(b, blen, n, "%s", got1 ? ":-1" : "-1");
                else
                        n += sg_scn3pr(b, blen, n, "%s%" PRIu64,
                                       got1 ? ":" : "", tp->l);
        } else if (0x1 & sel_mask) {    /* now must be NVMe */
                int lunhex = (sel_mask >> 4) & 0x3;

                if (1 == lunhex) {  /* -x (--lunhex) format */
                        n += sg_scn3pr(b, blen, n, "%s0x", got1 ? ":" : "");
                        n += sg_scn3pr(b, blen, n, "%04" PRIx32,
                                       (uint32_t)tp->l);
                } else if (lunhex > 1) { /* -xx (--lunhex twice) */
                        n += sg_scn3pr(b, blen, n, "%s0x", got1 ? ":" : "");
                        n += sg_scn3pr(b, blen, n, "%08" PRIx32,
                                       (uint32_t)tp->l);
                } else if (UINT32_MAX == tp->l)
                        n += sg_scn3pr(b, blen, n, "%s", got1 ? ":-1" : "-1");
                else
                        n += sg_scn3pr(b, blen, n, "%s%" PRIu32,
                                       got1 ? ":" : "", (uint32_t)tp->l);
        }
        if ((0 == n) && (blen > 0))
                b[0] = '\0';
        return b;
}

#if (HAVE_NVME && (! IGNORE_NVME))

static void
mk_nvme_tuple(struct addr_hctl * tp, int cdev_minor, int cntlid,
              uint32_t nsid)
{
        tp->h = NVME_HOST_NUM;
        tp->c = cdev_minor;
        tp->t = cntlid;
        // tp->l = nsid;
        sg_put_unaligned_le32(nsid, tp->lun_arr);
        memset(tp->lun_arr + 4, 0, 4);
        tp->l = nsid;
}

#endif

/* Returns remainder (*np % base) and replaces *np with (*np / base).
 * base needs to be > 0 */
static unsigned int
do_div_rem(uint64_t * np, unsigned int base)
{
        unsigned int res;

        res = *np % base;
        *np /= base;
        return res;
}

enum string_size_units {
        STRING_UNITS_10 = 0,    /* use powers of 10^3 (standard SI) */
        STRING_UNITS_2,         /* use binary powers of 2^10, ki, Mi */
};

/**
 * size2string - get the size in the specified units
 * @size:       The size to be converted
 * @units:      units to use (powers of 1000 or 1024)
 * @buf:        buffer to format to
 * @len:        length of buffer
 *
 * This function yields a string formatted to 3 significant figures
 * giving the size in the required units.  Returns true on success or
 * false on failure.  @buf is always zero terminated.
 */
static bool
size2string(uint64_t size, const enum string_size_units units, char *buf,
            int len)
{
        int i, j;
        unsigned int res;
        uint64_t sf_cap;
        uint64_t remainder = 0;
        char tmp[8];
        static const char * units_10[] = {
                "B", "kB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB", NULL};
        static const char * units_2[] = {
                "B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB",
                NULL};
        /* designated initializer are C99 but not yet C++; g++ and clang++
         * accept them (with noise) */
#ifdef __cplusplus
        const char **units_str[] = {units_10, units_2, };
        const unsigned int divisor[] = {1000, 1024, };
#else
        const char **units_str[] = {
                [STRING_UNITS_10] =  units_10,
                [STRING_UNITS_2] = units_2,
        };
        const unsigned int divisor[] = {
                [STRING_UNITS_10] = 1000,
                [STRING_UNITS_2] = 1024,
        };
#endif

        tmp[0] = '\0';
        i = 0;
        if (size >= divisor[units]) {
                while ((size >= divisor[units]) && units_str[units][i]) {
                        remainder = do_div_rem(&size, divisor[units]);
                        i++;
                }

                sf_cap = size;
                for (j = 0; (sf_cap * 10) < 1000; ++j)
                        sf_cap *= 10;

                if (j) {
                        remainder *= 1000;
                        do_div_rem(&remainder, divisor[units]);
                        res = remainder;
                        snprintf(tmp, sizeof(tmp), ".%03u", res);
                        tmp[j+1] = '\0';
                }
        }

        res = size;
        snprintf(buf, len, "%u%s%s", res, tmp, units_str[units][i]);

        return true;
}


/* Compare <host:controller:target:lun> tuples (aka <h:c:t:l> or hctl) */
static int
cmp_hctl(const struct addr_hctl * le, const struct addr_hctl * ri)
{
        if (le->h == ri->h) {
                if (le->c == ri->c) {
                        if (le->t == ri->t)
                                return ((le->l == ri->l) ? 0 :
                                        ((le->l < ri->l) ? -1 : 1));
                        else
                                return (le->t < ri->t) ? -1 : 1;
                } else
                        return (le->c < ri->c) ? -1 : 1;
        } else
                return (le->h < ri->h) ? -1 : 1;
}

static void
invalidate_hctl(struct addr_hctl * p)
{
        if (p) {
                p->h = -1;
                p->c = -1;
                p->t = -1;
                p->l = UINT64_LAST;
                /* le or be, it matters not; writing 0xff bytes */
                sg_put_unaligned_le64(p->l, p->lun_arr);
        }
}

/* Return 1 for directory entry that is link or directory (other than
 * a directory name starting with dot). Else return 0.  */
static int
first_dir_scan_select(const struct dirent * s)
{
        if (FT_OTHER != aa_first.ft)
                return 0;
        if (! dir_or_link(s, NULL))
                return 0;
        my_strcopy(aa_first.name, s->d_name, LMAX_NAME);
        aa_first.ft = FT_CHAR;  /* dummy */
        aa_first.d_type = s->d_type;
        return 1;
}

/* Selects symlinks and directories that don't start with "." */
static int
sub_dir_scan_select(const struct dirent * s)
{
        return (dir_or_link(s, NULL)) ? 1 : 0;
}

/* Selects symlinks and directories that don't start with "." as long as
 * they contain the string "scsi_disk". */
static int
sd_dir_scan_select(const struct dirent * s)
{
        return (dir_or_link(s, "scsi_disk")) ? 1 : 0;
}

/* Return 1 for directory entry that is link or directory (other than a
 * directory name starting with dot) that contains "block". Else return 0.
 */
static int
block_dir_scan_select(const struct dirent * s)
{
        return (dir_or_link(s, "block")) ? 1 : 0;
}

typedef int (* dirent_select_fn) (const struct dirent *);

/* Scans directory dir_name, selecting elements on the basis of fn (NULL
 * select all), into an unsorted list. The first item is assumed to be
 * directories (or symlinks to) and it is appended, after a '/' to dir_name.
 * Then if sub_str is found in that dir_name, it selects items that are
 * directories or symlinks, the first of which is appended, after a '/',
 * to dir_name. If conditions are met true is return, elae false.
 */
static bool
sub_scan(char * dir_name, const char * sub_str, dirent_select_fn fn)
{
        int num, k, len;
        struct dirent ** namelist;

        num = scandir(dir_name, &namelist, fn, NULL);
        if (num <= 0)
                return false;
        len = strlen(dir_name);
        if (len >= LMAX_PATH)
                return false;
        snprintf(dir_name + len, LMAX_PATH - len, "/%s", namelist[0]->d_name);

        for (k = 0; k < num; ++k)
                free(namelist[k]);
        free(namelist);

        if (strstr(dir_name, sub_str) == 0) {
                num = scandir(dir_name, &namelist, sub_dir_scan_select, NULL);
                if (num <= 0)
                        return false;
                len = strlen(dir_name);
                if (len >= LMAX_PATH)
                        return false;
                snprintf(dir_name + len, LMAX_PATH - len, "/%s",
                         namelist[0]->d_name);

                for (k = 0; k < num; ++k)
                        free(namelist[k]);
                free(namelist);
        }
        return true;
}

/* Scan for block:sdN or block/sdN directory in
 * /sys/bus/scsi/devices/h:c:t:l  */
static bool
block_scan(char * dir_name)
{
        return sub_scan(dir_name, "block:", block_dir_scan_select);
}

/* Scan for scsi_disk:h:c:t:l or scsi_disk/h:c:t:l directory in
 * /sys/bus/scsi/devices/h:c:t:l  */
static bool
sd_scan(char * dir_name)
{
        return sub_scan(dir_name, "scsi_disk:", sd_dir_scan_select);
}

static int
enclosure_device_dir_scan_select(const struct dirent * s)
{
        if (dir_or_link(s, "enclosure_device")) {
                my_strcopy(enclosure_device.name, s->d_name,
                           LMAX_NAME);
                enclosure_device.ft = FT_CHAR;  /* dummy */
                enclosure_device.d_type = s->d_type;
                return 1;
        }
        return 0;
}

/* Return true for directory entry that is link or directory (other than a
 * directory name starting with dot) that contains "enclosure_device".
 * Else return false.  */
static bool
enclosure_device_scan(const char * dir_name, const struct lsscsi_opts * op)
{
        int num, k;
        struct dirent ** namelist;

        num = scandir(dir_name, &namelist, enclosure_device_dir_scan_select,
                      NULL);
        if (num < 0) {
                if (op->verbose > 0) {
                        int n = 0;
                        int elen = sizeof(errpath);

                        n += sg_scn3pr(errpath, elen, n, "%s: scandir: ",
                                       __func__);
                        sg_scn3pr(errpath, elen, n, "%s", dir_name);
                        perror(errpath);
                }
                return false;
        }
        for (k = 0; k < num; ++k)
                free(namelist[k]);
        free(namelist);
        return !! num;
}

/* scan for directory entry that is either a symlink or a directory. Returns
 * number found or -1 for error. */
static int
scan_for_first(const char * dir_name, const struct lsscsi_opts * op)
{
        int num, k;
        struct dirent ** namelist;

        aa_first.ft = FT_OTHER;
        num = scandir(dir_name, &namelist, first_dir_scan_select, NULL);
        if (num < 0) {
                if (op->verbose > 0) {
                        int n = 0;
                        int elen = sizeof(errpath);

                        n += sg_scn3pr(errpath, elen, n, "%s: scandir: ",
                                       __func__);
                        sg_scn3pr(errpath, elen, n, "%s", dir_name);
                        perror(errpath);
                }
                return -1;
        }
        for (k = 0; k < num; ++k)
                free(namelist[k]);
        free(namelist);
        return num;
}

/* Assume at most 1 of the subdirectory/symlinks from the scanned directory
 * matches the strings in the strncmp() calls below. */
static int
non_sg_dir_scan_select(const struct dirent * s)
{
        int len;

        if (FT_OTHER != non_sg.ft)
                return 0;
        if (! dir_or_link(s, NULL))
                return 0;
        if (0 == strncmp("scsi_changer", s->d_name, 12)) {
                my_strcopy(non_sg.name, s->d_name, LMAX_NAME);
                non_sg.ft = FT_CHAR;
                non_sg.d_type = s->d_type;
                return 1;
        } else if (0 == strncmp("block", s->d_name, 5)) {
                my_strcopy(non_sg.name, s->d_name, LMAX_NAME);
                non_sg.ft = FT_BLOCK;
                non_sg.d_type = s->d_type;
                return 1;
        } else if (0 == strcmp("tape", s->d_name)) {
                my_strcopy(non_sg.name, s->d_name, LMAX_NAME);
                non_sg.ft = FT_CHAR;
                non_sg.d_type = s->d_type;
                return 1;
        } else if (0 == strncmp("scsi_tape:st", s->d_name, 12)) {
                len = strlen(s->d_name);
                if (isdigit(s->d_name[len - 1])) {
                        /* want 'st<num>' symlink only */
                        my_strcopy(non_sg.name, s->d_name, LMAX_NAME);
                        non_sg.ft = FT_CHAR;
                        non_sg.d_type = s->d_type;
                        return 1;
                } else
                        return 0;
        } else if (0 == strncmp("onstream_tape:os", s->d_name, 16)) {
                my_strcopy(non_sg.name, s->d_name, LMAX_NAME);
                non_sg.ft = FT_CHAR;
                non_sg.d_type = s->d_type;
                return 1;
        } else
                return 0;
}

/* Want to know the primary device sysfs directory (if any). Ignore the scsi
 * generic sysfs directory.  Returns number found (expected to be 1 or 0) or
 * -1 for error */
static int
non_sg_scan(const char * dir_name, const struct lsscsi_opts * op)
{
        int num, k;
        struct dirent ** namelist;

        non_sg.ft = FT_OTHER;
        num = scandir(dir_name, &namelist, non_sg_dir_scan_select, NULL);
        if (num < 0) {
                if (op->verbose > 0) {
                        sg_scnpr(errpath, LMAX_PATH, "%s: scandir: %s",
                                 __func__, dir_name);
                        perror(errpath);
                }
                return -1;
        }
        for (k = 0; k < num; ++k)
                free(namelist[k]);
        free(namelist);
        return num;
}


static int
sg_dir_scan_select(const struct dirent * s)
{
        if (FT_OTHER != aa_sg.ft)
                return 0;
        if (dir_or_link(s, "scsi_generic")) {
                my_strcopy(aa_sg.name, s->d_name, LMAX_NAME);
                aa_sg.ft = FT_CHAR;
                aa_sg.d_type = s->d_type;
                return 1;
        } else
                return 0;
}

/* Returns number of directories or links starting with "scsi_generic"
 * found or -1 for error. */
static int
sg_scan(const char * dir_name)
{
        int num, k;
        struct dirent ** namelist;

        aa_sg.ft = FT_OTHER;
        num = scandir(dir_name, &namelist, sg_dir_scan_select, NULL);
        if (num < 0)
                return -1;
        for (k = 0; k < num; ++k)
                free(namelist[k]);
        free(namelist);
        return num;
}

#if (HAVE_NVME && (! IGNORE_NVME))

static int
ng_dir_scan_select(const struct dirent * s)
{
        if (FT_OTHER != aa_ng.ft)
                return 0;
        if (dir_or_link(s, "ng")) {
                my_strcopy(aa_ng.name, s->d_name, LMAX_NAME);
                aa_ng.ft = FT_CHAR;
                aa_ng.d_type = s->d_type;
                return 1;
        } else
                return 0;
}

/* Returns number of directories or links starting with "ng"
 * found or -1 for error. */
static int
ng_scan(const char * dir_name)
{
        int num, k;
        struct dirent ** namelist;

        aa_ng.ft = FT_OTHER;
        num = scandir(dir_name, &namelist, ng_dir_scan_select, NULL);
        if (num < 0)
                return -1;
        for (k = 0; k < num; ++k)
                free(namelist[k]);
        free(namelist);
        return num;
}

#endif

static int
sas_port_dir_scan_select(const struct dirent * s)
{
        return (dir_or_link(s, "port-")) ? 1 : 0;
}

static int
sas_port_scan(const char * dir_name, struct dirent ***port_list)
{
        int num;
        struct dirent ** namelist;

        namelist = NULL;
        num = scandir(dir_name, &namelist, sas_port_dir_scan_select, NULL);
        if (num < 0) {
                *port_list = NULL;
                return -1;
        }
        *port_list = namelist;
        return num;
}


static int
sas_low_phy_dir_scan_select(const struct dirent * s)
{
        int n, m;
        char * cp;

        if (dir_or_link(s, "phy")) {
                if (0 == strlen(sas_low_phy))
                        my_strcopy(sas_low_phy, s->d_name, LMAX_NAME);
                else {
                        cp = (char *)strrchr(s->d_name, ':');
                        if (NULL == cp)
                                return 0;
                        n = atoi(cp + 1);
                        cp = strrchr(sas_low_phy, ':');
                        if (NULL == cp)
                                return 0;
                        m = atoi(cp + 1);
                        if (n < m)
                                my_strcopy(sas_low_phy, s->d_name, LMAX_NAME);
                }
                return 1;
        } else
                return 0;
}

static int
sas_low_phy_scan(const char * dir_name, struct dirent ***phy_list)
{
        int num, k;
        struct dirent ** namelist = NULL;

        memset(sas_low_phy, 0, sizeof(sas_low_phy));
        num = scandir(dir_name, &namelist, sas_low_phy_dir_scan_select, NULL);
        if (num < 0)
                return -1;
        if (! phy_list) {
                for (k = 0; k < num; ++k)
                        free(namelist[k]);
                free(namelist);
        } else
                *phy_list = namelist;
        return num;
}

static int
iscsi_target_dir_scan_select(const struct dirent * s)
{
        int off;
        char buff[LMAX_PATH];
        struct stat a_stat;

        if (dir_or_link(s, "session")) {
                iscsi_tsession_num = atoi(s->d_name + 7);
                my_strcopy(buff, iscsi_dir_name, LMAX_PATH);
                off = strlen(buff);
                snprintf(buff + off, sizeof(buff) - off,
                         "/%s/target%d:%d:%d", s->d_name, iscsi_target_hct->h,
                         iscsi_target_hct->c, iscsi_target_hct->t);
                if ((stat(buff, &a_stat) >= 0) && S_ISDIR(a_stat.st_mode))
                        return 1;
                else
                        return 0;
        } else
                return 0;
}

static int
iscsi_target_scan(const char * dir_name, const struct addr_hctl * hctl)
{
        int num, k;
        struct dirent ** namelist;

        iscsi_dir_name = dir_name;
        iscsi_target_hct = hctl;
        iscsi_tsession_num = -1;
        num = scandir(dir_name, &namelist, iscsi_target_dir_scan_select,
                      NULL);
        if (num < 0) {
                num = -1;
                goto fini;
        }
        for (k = 0; k < num; ++k)
                free(namelist[k]);
        free(namelist);
fini:
        iscsi_dir_name = NULL;          /* so analyzer doesn't see a leak */
        iscsi_target_hct = NULL;        /* so analyzer doesn't see a leak */
        return num;
}


/* If 'dir_name'/'base_name' is a directory chdir to it. If that is successful
   return true, else false */
static bool
if_directory_chdir(const char * dir_name, const char * base_name)
{
        char b[LMAX_PATH];
        struct stat a_stat;

        snprintf(b, sizeof(b), "%s/%s", dir_name, base_name);
        if (stat(b, &a_stat) < 0)
                return false;
        if (S_ISDIR(a_stat.st_mode)) {
                if (chdir(b) < 0)
                        return false;
                return true;
        }
        return false;
}

/* If 'dir_name'/generic is a directory chdir to it. If that is successful
   return true. Otherwise look a directory of the form
   'dir_name'/scsi_generic:sg<n> and if found chdir to it and return true.
   Otherwise return false. */
static bool
if_directory_ch2generic(const char * dir_name)
{
        char b[LMAX_PATH];
        struct stat a_stat;
        static const char * old_name = "generic";

        snprintf(b, sizeof(b), "%s/%s", dir_name, old_name);
        if ((stat(b, &a_stat) >= 0) && S_ISDIR(a_stat.st_mode)) {
                if (chdir(b) < 0)
                        return false;
                return true;
        }
        /* No "generic", so now look for "scsi_generic:sg<n>" */
        if (1 != sg_scan(dir_name))
                return false;
        snprintf(b, sizeof(b), "%s/%s", dir_name, aa_sg.name);
        if (stat(b, &a_stat) < 0)
                return false;
        if (S_ISDIR(a_stat.st_mode)) {
                if (chdir(b) < 0)
                        return false;
                return true;
        }
        return false;
}

/* If 'dir_name'/'base_name' is found places corresponding value in 'value'
 * and returns true . Else returns false. 'base_name' may be NULL. */
static bool
get_value(const char * dir_name, const char * base_name, char * value,
          int max_value_len)
{
        int len;
        FILE * f;
        char b[LMAX_PATH];

        if (base_name)
                snprintf(b, sizeof(b), "%s/%s", dir_name, base_name);
        else
                snprintf(b, sizeof(b), "%s", dir_name);
        if (NULL == (f = fopen(b, "r"))) {
                return false;
        }
        if (NULL == fgets(value, max_value_len, f)) {
                /* assume empty */
                value[0] = '\0';
                fclose(f);
                return true;
        }
        len = strlen(value);
        if ((len > 0) && (value[len - 1] == '\n'))
                value[len - 1] = '\0';
        fclose(f);
        return true;
}

/* Concatenates first three arguments with "/" as separator and opens a
 * file with that name and places its contents in 'value' . Both
 * 'middle_name' and 'base_name' may be NULL, if so ignored. */
static bool
get2_value(const char * dir_name, const char * middle_name,
           const char * base_name, char * value, int max_value_len)
{
        char b[LMAX_PATH];

        if (middle_name)
                snprintf(b, sizeof(b), "%s/%s", dir_name, middle_name);
        else
                snprintf(b, sizeof(b), "%s", dir_name);
        return get_value(b, base_name, value, max_value_len);
}


/* Allocate dev_node_list and collect info on every char and block devices
 * in /dev but not its subdirectories. This list excludes symlinks, even if
 * they are to devices. */
static void
collect_dev_nodes(void)
{
        size_t dnl_sz = sizeof(struct dev_node_list);
        struct dirent *dep;
        DIR *dirp;
        struct dev_node_list *cur_list, *prev_list;
        struct dev_node_entry *cur_ent;
        char device_path[LMAX_DEVPATH];
        struct stat stats;

        if (dev_node_listhead)
                return; /* already collected nodes */

        dev_node_listhead = (struct dev_node_list *)calloc(1, dnl_sz);
        if (! dev_node_listhead)
                return;

        cur_list = dev_node_listhead;
        cur_list->next = NULL;
        cur_list->count = 0;

        dirp = opendir(dev_dir_s);
        if (dirp == NULL)
                return;

        while (1) {
                dep = readdir(dirp);
                if (dep == NULL)
                        break;

                snprintf(device_path, sizeof(device_path), "%s/%s",
                         dev_dir_s, dep->d_name);
                /* device_path[LMAX_PATH] = '\0'; */

                /* lstat() does not follow symlinks, stat() does */
                if (lstat(device_path, &stats))
                        continue;       /* unlikely: error */

                /* Skip non-block/char files. */
                if ((! S_ISBLK(stats.st_mode)) && (! S_ISCHR(stats.st_mode)))
                        continue;

                /* Add to the list. */
                if (cur_list->count >= DEV_NODE_LIST_ENTRIES) {
                        prev_list = cur_list;
                        cur_list = (struct dev_node_list *)calloc(1, dnl_sz);
                        if (! cur_list)
                                break;
                        prev_list->next = cur_list;
                        cur_list->next = NULL;
                        cur_list->count = 0;
                }

                cur_ent = &cur_list->nodes[cur_list->count];
                cur_ent->maj = major(stats.st_rdev);
                cur_ent->min = minor(stats.st_rdev);
                if (S_ISBLK(stats.st_mode))
                        cur_ent->d_typ = BLK_DEV;
                else if (S_ISCHR(stats.st_mode))
                        cur_ent->d_typ = CHR_DEV;
                cur_ent->mtime = stats.st_mtime;
                my_strcopy(cur_ent->name, device_path, sizeof(cur_ent->name));

                cur_list->count++;
        }
        closedir(dirp);
}

/* Free dev_node_list. */
static void
free_dev_node_list(void)
{
        if (dev_node_listhead) {
                struct dev_node_list *cur_list, *next_list;

                cur_list = dev_node_listhead;
                while (cur_list) {
                        next_list = cur_list->next;
                        free(cur_list);
                        cur_list = next_list;
                }

                dev_node_listhead = NULL;
        }
}

/* Given a path to a class device, find the most recent device node with
 * matching major/minor and type. Outputs to node which is assumed to be at
 * least LMAX_NAME bytes long. Returns true if match found, false
 * otherwise. */
static bool
get_dev_node(const char * wd, char * node, enum dev_type d_typ)
{
        bool match_found = false;
        unsigned int k = 0;
        unsigned int maj, min;
        time_t newest_mtime = 0;
        struct dev_node_entry *cur_ent;
        struct dev_node_list *cur_list;
        char value[LMAX_NAME];

        /* assume 'node' is at least 2 bytes long */
        memcpy(node, "-", 2);
        if (dev_node_listhead == NULL) {
                collect_dev_nodes();
                if (dev_node_listhead == NULL)
                        goto fini;
        }

        /* Get the major/minor for this device. */
        if (!get_value(wd, dv_s, value, LMAX_NAME))
                goto fini;
        if (2 != sscanf(value, "%u:%u", &maj, &min))
                goto fini;

        /* Search the node list for the newest match on this major/minor. */
        cur_list = dev_node_listhead;

        while (1) {
                if (k >= cur_list->count) {
                        cur_list = cur_list->next;
                        if (! cur_list)
                                break;
                        k = 0;
                }

                cur_ent = &cur_list->nodes[k];
                k++;

                if ((maj == cur_ent->maj) &&
                    (min == cur_ent->min) &&
                    (d_typ == cur_ent->d_typ)) {
                        if ((! match_found) ||
                            (difftime(cur_ent->mtime, newest_mtime) > 0)) {
                                newest_mtime = cur_ent->mtime;
                                my_strcopy(node, cur_ent->name, LMAX_NAME);
                        }
                        match_found = true;
                }
        }

fini:
        return match_found;
}

/* Allocate disk_wwn_node_list and collect info on every node in
 * /dev/disk/by-id/scsi-* that does not contain "part" . Returns
 * number of wwn nodes collected, 0 for already collected and
 * -1 for error. */
static int
collect_disk_wwn_nodes(bool wwn_twice)
{
        int k;
        int num = 0;
        size_t dwnl_sz = sizeof(struct disk_wwn_node_list);
        struct disk_wwn_node_list *cur_list, *prev_list;
        struct disk_wwn_node_entry *cur_ent;
        DIR *dirp;
        struct dirent *dep;
        char device_path[PATH_MAX + 1];
        char symlink_path[PATH_MAX + 1];
        struct stat stats;

        if (disk_wwn_node_listhead)
                return num; /* already collected nodes */

        disk_wwn_node_listhead =
                         (struct disk_wwn_node_list *)calloc(1, dwnl_sz);
        if (! disk_wwn_node_listhead)
                return -1;

        cur_list = disk_wwn_node_listhead;

        dirp = opendir(dev_disk_byid_dir);
        if (dirp == NULL)
                return -1;

        if (wwn_twice)
                goto wwn_really;

        while (1) {
                dep = readdir(dirp);
                if (dep == NULL)
                        break;
                if (memcmp("scsi-", dep->d_name, 5))
                        continue;       /* needs to start with "scsi-" */
                if (strstr(dep->d_name, "part"))
                        continue;       /* skip if contains "part" */
                /* accepted device identification VPD page designator types */
                if (dep->d_name[5] != '3' &&    /* NAA */
                    dep->d_name[5] != '2' &&    /* EUI-64 based */
                    dep->d_name[5] != '8')      /* SCSI name string (iSCSI) */
                        continue;       /* skip for invalid identifier */

                snprintf(device_path, PATH_MAX, "%s/%s", dev_disk_byid_dir,
                         dep->d_name);
                device_path[PATH_MAX] = '\0';
                if (lstat(device_path, &stats))
                        continue;       /* unlikely: error */
                if (! S_ISLNK(stats.st_mode))
                        continue;       /* Skip non-symlinks */
                if ((k = readlink(device_path, symlink_path, PATH_MAX)) < 1)
                        continue;       /* expect 1 or more chars in symlink */
                symlink_path[k] = '\0';

                /* Add to the list. */
                if (cur_list->count >= DISK_WWN_NODE_LIST_ENTRIES) {
                        prev_list = cur_list;
                        cur_list = (struct disk_wwn_node_list *)
                                                        calloc(1, dwnl_sz);
                        if (! cur_list)
                                break;
                        prev_list->next = cur_list;
                }

                cur_ent = &cur_list->nodes[cur_list->count];
                my_strcopy(cur_ent->wwn, "0x", 3);
                /* step over designator type */
                my_strcopy(cur_ent->wwn + 2, dep->d_name + 6,
                           sizeof(cur_ent->wwn) - 2);
                my_strcopy(cur_ent->disk_bname, basename(symlink_path),
                           sizeof(cur_ent->disk_bname));
                cur_list->count++;
                ++num;
        }
        closedir(dirp);
        return num;
wwn_really:
        while (1) {
                dep = readdir(dirp);
                if (dep == NULL)
                        break;
                if (memcmp("wwn-", dep->d_name, 4))
                        continue;       /* needs to start with "wwn-" */
                if (strstr(dep->d_name, "part"))
                        continue;       /* skip if contains "part" */

                snprintf(device_path, PATH_MAX, "%s/%s", dev_disk_byid_dir,
                         dep->d_name);
                device_path[PATH_MAX] = '\0';
                if (lstat(device_path, &stats))
                        continue;       /* unlikely: error */
                if (! S_ISLNK(stats.st_mode))
                        continue;       /* Skip non-symlinks */
                if ((k = readlink(device_path, symlink_path, PATH_MAX)) < 1)
                        continue;
                symlink_path[k] = '\0';

                /* Add to the list. */
                if (cur_list->count >= DISK_WWN_NODE_LIST_ENTRIES) {
                        prev_list = cur_list;
                        cur_list = (struct disk_wwn_node_list *)
                                                        calloc(1, dwnl_sz);
                        if (! cur_list)
                                break;
                        prev_list->next = cur_list;
                }

                cur_ent = &cur_list->nodes[cur_list->count];
                my_strcopy(cur_ent->wwn, dep->d_name + 4,
                           sizeof(cur_ent->wwn));
                my_strcopy(cur_ent->disk_bname, basename(symlink_path),
                           sizeof(cur_ent->disk_bname));
                cur_list->count++;
                ++num;
        }
        closedir(dirp);
        return num;
}

/* Free disk_wwn_node_list. */
static void
free_disk_wwn_node_list(void)
{
        if (disk_wwn_node_listhead) {
                struct disk_wwn_node_list *cur_list, *next_list;

                cur_list = disk_wwn_node_listhead;
                while (cur_list) {
                        next_list = cur_list->next;
                        free(cur_list);
                        cur_list = next_list;
                }

                disk_wwn_node_listhead = NULL;
        }
}

/* Given a path to a class device, find the most recent device node with
   matching major/minor. Returns true if match found, false otherwise. */
static bool
get_disk_wwn(const char *wd, char * wwn_str, int max_wwn_str_len,
             bool wwn_twice)
{
        unsigned int k = 0;
        char * bn;
        struct disk_wwn_node_list *cur_list;
        struct disk_wwn_node_entry *cur_ent;
        char name[LMAX_PATH];

        my_strcopy(name, wd, sizeof(name));
        name[sizeof(name) - 1] = '\0';
        bn = basename(name);
        if (disk_wwn_node_listhead == NULL) {
                collect_disk_wwn_nodes(wwn_twice);
                if (disk_wwn_node_listhead == NULL)
                        return false;
        }
        cur_list = disk_wwn_node_listhead;
        while (1) {
                if (k >= cur_list->count) {
                        cur_list = cur_list->next;
                        if (! cur_list)
                                break;
                        k = 0;
                }
                cur_ent = &cur_list->nodes[k];
                k++;
                if (0 == strcmp(cur_ent->disk_bname, bn)) {
                        my_strcopy(wwn_str, cur_ent->wwn, max_wwn_str_len);
                        wwn_str[max_wwn_str_len - 1] = '\0';
                        return true;
                }
        }
        return false;
}

/*
 * Look up a device node in a directory with symlinks to device nodes.
 * @dir: Directory to examine, e.g. "/dev/disk/by-id".
 * @pfx: Prefix of the symlink, e.g. "scsi-".
 * @priority: Identifier priority of the @pfx prefix from highest to lowest.
 * @dev: Device node to look up, e.g. "/dev/sda".
 * Returns a pointer to the name of the symlink without the prefix if a match
 * has been found. When @priority is supplied the best available symlink
 * is chosen by comparing first character of the identifier within
 * the @priority set.
 * Side effect: changes the working directory to @dir.
 * Note: The caller must free the pointer returned by this function.
 */
static char *
lookup_dev(const char *dir, const char *pfx, const char *priority,
           const char *dev)
{
        unsigned int st_rdev;
        DIR *dirp;
        struct dirent *entry;
        char *result = NULL;
        struct stat stats;

        if (stat(dev, &stats) < 0)
                goto out;
        st_rdev = stats.st_rdev;
        if (chdir(dir) < 0)
                goto out;
        dirp = opendir(dir);
        if (!dirp)
                goto out;
        while ((entry = readdir(dirp)) != NULL) {
                if (stat(entry->d_name, &stats) >= 0 &&
                    stats.st_rdev == st_rdev &&
                    strncmp(entry->d_name, pfx, strlen(pfx)) == 0) {
                        char *nm = entry->d_name + strlen(pfx);

                        if (!priority || *nm == *priority) {
                                free(result);
                                result = strdup(nm);
                                break;
                        }
                        if (!result ||
                            ((strchr(priority, *nm) != NULL) &&
                             (strchr(priority, *nm) <
                              strchr(priority, *result)))) {
                                free(result);
                                result = strdup(nm);
                        }
                }
        }
        closedir(dirp);
out:
        return result;
}

/*
 * Obtain the SCSI ID of a disk.
 * @dev_node: Device node of the disk, e.g. "/dev/sda".
 * Return value: pointer to the SCSI ID if lookup succeeded or NULL if lookup
 * failed.
 * Note: The caller must free the returned buffer with free().
 */
static char *
get_disk_scsi_id(const char *dev_node, bool wo_prefix)
{
        char *scsi_id = NULL;
        DIR *dir;
        struct dirent *entry;
        char holder[LMAX_PATH + 6];
        char sys_block[LMAX_PATH];

        scsi_id = lookup_dev(dev_disk_byid_dir, "scsi-", "328S10", dev_node);
        if (scsi_id) {
                if (wo_prefix) {
                        size_t len = strlen(scsi_id);

                        if (len > 1) {
                                memmove(scsi_id, scsi_id + 1, len - 1);
                                scsi_id[len - 1] = '\0';
                        }
                }
                goto out;
        }
        scsi_id = lookup_dev(dev_disk_byid_dir, "dm-uuid-mpath-", NULL,
                             dev_node);
        if (scsi_id)
                goto out;
        scsi_id = lookup_dev(dev_disk_byid_dir, "usb-", NULL, dev_node);
        if (scsi_id)
                goto out;
        snprintf(sys_block, sizeof(sys_block), "%s/class/block/%s/holders",
                 sysfsroot, dev_node + 5);
        dir = opendir(sys_block);
        if (!dir)
                goto out;
        while ((entry = readdir(dir)) != NULL) {
                snprintf(holder, sizeof(holder), "/dev/%s", entry->d_name);
                scsi_id = get_disk_scsi_id(holder, wo_prefix); /* recurse */
                if (scsi_id)
                        break;
        }
        closedir(dir);
out:
        return scsi_id;
}

/* Fetch USB device name string (form "<b>-<p1>[.<p2>]+:<c>.<i>") given
 * either a SCSI host name or devname (i.e. "h:c:t:l") string. If detected
 * return 'b' (pointer to start of USB device name string which is null
 * terminated), else return NULL.
 */
static char *
get_usb_devname(const char * hname, const char * devname, char * b, int b_len)
{
        int len;
        char * c2p;
        char * cp;
        const char * np;
        char bf2[LMAX_PATH];
        char buff[LMAX_DEVPATH];

        if (hname) {
                snprintf(buff, sizeof(buff), "%s%s", sysfsroot, scsi_host_s);
                np = hname;
        } else if (devname) {
                snprintf(buff, sizeof(buff), "%s/%s/%s", sysfsroot, cl_s,
                         sdev_s);
                np = devname;
        } else
                return NULL;
        if (if_directory_chdir(buff, np) && getcwd(bf2, sizeof(bf2)) &&
            strstr(bf2, "usb")) {
                if (b_len > 0)
                        b[0] = '\0';
                if ((cp = strstr(bf2, "/host"))) {
                        len = (cp - bf2) - 1;
                        if ((len > 0) &&
                            ((c2p = (char *)memrchr(bf2, '/', len)))) {
                                len = cp - ++c2p;
                                snprintf(b, b_len, "%.*s", len, c2p);
                        }
                }
                return b;
        }
        return NULL;
}

#define VPD_DEVICE_ID 0x83
#define VPD_ASSOC_LU 0
#define VPD_ASSOC_TPORT 1
#define TPROTO_ISCSI 5

/* Iterates to next designation descriptor in the device identification
 * VPD page. The 'initial_desig_desc' should point to start of first
 * descriptor with 'page_len' being the number of valid bytes in that
 * and following descriptors. To start, 'off' should point to a negative
 * value, thereafter it should point to the value yielded by the previous
 * call. If 0 returned then 'initial_desig_desc + *off' should be a valid
 * descriptor; returns -1 if normal end condition and -2 for an abnormal
 * termination. Matches association, designator_type and/or code_set when
 * any of those values are greater than or equal to zero. */
static int
sg_vpd_dev_id_iter(const uint8_t * initial_desig_desc, int page_len,
                   int * off, int m_assoc, int m_desig_type, int m_code_set)
{
        const uint8_t * bp;
        int k, c_set, assoc, desig_type;

        for (k = *off, bp = initial_desig_desc ; (k + 3) < page_len; ) {
                k = (k < 0) ? 0 : (k + bp[k + 3] + 4);
                if ((k + 4) > page_len)
                        break;
                c_set = (bp[k] & 0xf);
                if ((m_code_set >= 0) && (m_code_set != c_set))
                        continue;
                assoc = ((bp[k + 1] >> 4) & 0x3);
                if ((m_assoc >= 0) && (m_assoc != assoc))
                        continue;
                desig_type = (bp[k + 1] & 0xf);
                if ((m_desig_type >= 0) && (m_desig_type != desig_type))
                        continue;
                *off = k;
                return 0;
        }
        return (k == page_len) ? -1 : -2;
}

/* Fetch logical unit (LU) name given the device name in the form:
 * h:c:t:l tuple string (e.g. "2:0:1:0"). This is fetched via sysfs (lk 3.15
 * and later) in vpd_pg83. For later ATA and SATA devices this may be its
 * WWN. Normally take the first found in this order: NAA, EUI-64 * then SCSI
 * name string. However if a SCSI name string is present and the protocol is
 * iSCSI (target port checked) then the SCSI name string is preferred. If
 * none of the above are present then check for T10 Vendor ID
 * (designator_type=1) and use if available. */
static char *
get_lu_name(const char * devname, char * b, int b_len, bool want_prefix)
{
        int fd, res, len, dlen, sns_dlen, off, k, n;
        uint8_t *bp;
        char *cp;
        char buff[LMAX_DEVPATH];
        uint8_t u[512];
        uint8_t u_sns[512];
        struct stat a_stat;

        if ((NULL == b) || (b_len < 1))
                return b;
        b[0] = '\0';
        snprintf(buff, sizeof(buff), "%s/%s/%s/%s/device/vpd_pg83",
                 sysfsroot, cl_s, sdev_s, devname);
        if (! ((stat(buff, &a_stat) >= 0) && S_ISREG(a_stat.st_mode)))
                return b;
        if ((fd = open(buff, O_RDONLY)) < 0)
                return b;
        res = read(fd, u, sizeof(u));
        if (res <= 8) {
                close(fd);
                return b;
        }
        close(fd);
        if (VPD_DEVICE_ID != u[1])
                return b;
        len = sg_get_unaligned_be16(u + 2);
        if ((len + 4) != res)
                return b;
        bp = u + 4;
        cp = b;
        off = -1;
        if (0 == sg_vpd_dev_id_iter(bp, len, &off, VPD_ASSOC_LU,
                                    8 /* SCSI name string (sns) */,
                                    3 /* UTF-8 */)) {
                sns_dlen = bp[off + 3];
                memcpy(u_sns, bp + off + 4, sns_dlen);
                /* now want to check if this is iSCSI */
                off = -1;
                if (0 == sg_vpd_dev_id_iter(bp, len, &off, VPD_ASSOC_TPORT,
                                            8 /* SCSI name string (sns) */,
                                            3 /* UTF-8 */)) {
                        if ((0x80 & bp[1]) &&
                            (TPROTO_ISCSI == (bp[0] >> 4))) {
                                snprintf(b, b_len, "%.*s", sns_dlen, u_sns);
                                return b;
                        }
                }
        } else
                sns_dlen = 0;

        if (0 == sg_vpd_dev_id_iter(bp, len, &off, VPD_ASSOC_LU,
                                    3 /* NAA */, 1 /* binary */)) {
                dlen = bp[off + 3];
                if (! ((8 == dlen) || (16 == dlen)))
                        return b;
                if (want_prefix) {
                        if ((n = snprintf(cp, b_len, "naa.")) >= b_len)
                                n = b_len - 1;
                        cp += n;
                        b_len -= n;
                }
                for (k = 0; ((k < dlen) && (b_len > 1)); ++k) {
                        snprintf(cp, b_len, "%02x", bp[off + 4 + k]);
                        cp += 2;
                        b_len -= 2;
                }
        } else if (0 == sg_vpd_dev_id_iter(bp, len, &off, VPD_ASSOC_LU,
                                           2 /* EUI */, 1 /* binary */)) {
                dlen = bp[off + 3];
                if (! ((8 == dlen) || (12 == dlen) || (16 == dlen)))
                        return b;
                if (want_prefix) {
                        if ((n = snprintf(cp, b_len, "eui.")) >= b_len)
                                n = b_len - 1;
                        cp += n;
                        b_len -= n;
                }
                for (k = 0; ((k < dlen) && (b_len > 1)); ++k) {
                        snprintf(cp, b_len, "%02x", bp[off + 4 + k]);
                        cp += 2;
                        b_len -= 2;
                }
        } else if (0 == sg_vpd_dev_id_iter(bp, len, &off, VPD_ASSOC_LU,
                                           0xa /* UUID */,  1 /* binary */)) {
                dlen = bp[off + 3];
                if ((1 != ((bp[off + 4] >> 4) & 0xf)) || (18 != dlen)) {
                        snprintf(cp, b_len, "??");
                        /* cp += 2; */
                        /* b_len -= 2; */
                } else {
                        if (want_prefix) {
                                if ((n = snprintf(cp, b_len, "uuid.")) >=
                                    b_len)
                                        n = b_len - 1;
                                cp += n;
                                b_len -= n;
                        }
                        for (k = 0; (k < 16) && (b_len > 1); ++k) {
                                if ((4 == k) || (6 == k) || (8 == k) ||
                                    (10 == k)) {
                                        snprintf(cp, b_len, "-");
                                        ++cp;
                                        --b_len;
                                }
                                snprintf(cp, b_len, "%02x",
                                         (unsigned int)bp[off + 6 + k]);
                                cp += 2;
                                b_len -= 2;
                        }
                }
        } else if (sns_dlen > 0)
                snprintf(b, b_len, "%.*s", sns_dlen, u_sns);
        else if ((0 == sg_vpd_dev_id_iter(bp, len, &off, VPD_ASSOC_LU,
                                          0x1 /* T10 vendor ID */,  -1)) &&
                 ((bp[off] & 0xf) > 1 /* ASCII or UTF */)) {
                dlen = bp[off + 3];
                if (dlen < 8)
                        return b;       /* must have 8 byte T10 vendor id */
                if (want_prefix) {
                        if ((n = snprintf(cp, b_len, "t10.")) >= b_len)
                                n = b_len - 1;
                        cp += n;
                        b_len -= n;
                }
                snprintf(cp, b_len, "%.*s", dlen, bp + off + 4);
        }
        return b;
}

/* Parse colon_list into host/channel/target/lun ("hctl") array, return true
 * if successful, else false. colon_list should point at first character of
 * hctl (i.e. a digit) and yields a new value in *outp when true returned. */
static bool
parse_colon_list(const char * colon_list, struct addr_hctl * outp)
{
        int k;
        uint64_t z;
        const char * elem_end;

        if ((! colon_list) || (! outp))
                return false;
#if (HAVE_NVME && (! IGNORE_NVME))
        if ('N' == toupper((uint8_t)*colon_list)) {
                int val;

                outp->h = NVME_HOST_NUM;
                if ((0 == strncmp(colon_list, "nvme", 4)) &&
                    (1 == sscanf(colon_list + 4, "%d%n", &outp->c, &k)))
                        colon_list = colon_list + 4 + k;
                else
                        return false;

                while (*colon_list) {
                        if ('c' == *colon_list) {
                                if (1 == sscanf(colon_list + 1, "%d%n",
                                                &outp->t, &k)) {
                                        outp->t++;
                                        /* /sys/class/nvme/nvmeX/cntlid starts
                                         * from 1  */
                                        colon_list = colon_list + 1 + k;
                                } else
                                        break;
                        } else if ('n' == *colon_list) {
                                if (1 == sscanf(colon_list + 1, "%d%n", &val,
                                                &k)) {
                                        outp->l = val;
                                        colon_list = colon_list + 1 + k;
                                } else
                                        break;
                        } else if ('p' == *colon_list) {
                                /* partition number, ignoring assignment */
                                if (1 == sscanf(colon_list + 1, "%*d%n", &k)) {
                                        colon_list = colon_list + 1 + k;
                                } else
                                        break;
                        } else {
                                /* unmatched string */
                                break;
                        }
                }

                return true;
        } else if (1 != sscanf(colon_list, "%d", &outp->h))
                return false;
#else
        if (1 != sscanf(colon_list, "%d", &outp->h))
                return false;
#endif
        if (NULL == (elem_end = strchr(colon_list, ':')))
                return false;
        colon_list = elem_end + 1;
        if (1 != sscanf(colon_list, "%d", &outp->c))
                return false;
        if (NULL == (elem_end = strchr(colon_list, ':')))
                return false;
        colon_list = elem_end + 1;
        if (1 != sscanf(colon_list, "%d", &outp->t))
                return false;
        if (NULL == (elem_end = strchr(colon_list, ':')))
                return false;
        colon_list = elem_end + 1;
        if (1 != sscanf(colon_list, "%" SCNu64 , &outp->l))
                return false;
        z = outp->l;
        for (k = 0; k < 8; k += 2, z >>= 16)
                sg_put_unaligned_be16((uint16_t)z, outp->lun_arr + k);
        return true;
}

/* Print enclosure device link from the rport- or end_device- */
static void
print_enclosure_device(const char *devname, const char *path,
                       struct lsscsi_opts * op)
{
        sgj_state * jsp = &op->json_st;
        struct addr_hctl hctl;
        char b[LMAX_PATH];

        if (parse_colon_list(devname, &hctl)) {
                snprintf(b, sizeof(b),
                         "%s/device/target%d:%d:%d/%d:%d:%d:%" PRIu64,
                         path, hctl.h, hctl.c, hctl.t,
                         hctl.h, hctl.c, hctl.t, hctl.l);
                if (enclosure_device_scan(b, op) > 0)
                        sgj_pr_hr(jsp, "  %s\n", enclosure_device.name);
        }
}

/*
 * Obtain the GUID of the InfiniBand port associated with SCSI host number h
 * by stripping prefix fe80:0000:0000:0000: from GID 0. An example:
 * 0002:c903:00a0:5de2.
 */
static void
get_local_srp_gid(const int h, char *b, int b_len)
{
        int port;
        char buff[LMAX_DEVPATH];
        char value[LMAX_NAME];

        snprintf(buff, sizeof(buff), "%s%shost%d", sysfsroot, scsi_host_s, h);
        if (!get_value(buff, "local_ib_port", value, sizeof(value)))
                return;
        if (sscanf(value, "%d", &port) != 1)
                return;
        if (!get_value(buff, "local_ib_device", value, sizeof(value)))
                return;
        snprintf(buff, sizeof(buff), "%s/class/infiniband/%s/ports/%d/gids",
                 sysfsroot, value, port);
        if (!get_value(buff, "0", value, sizeof(value)))
                return;
        if (strlen(value) > 20)
                snprintf(b, b_len, "%s", value + 20);
}

/*
 * Obtain the original GUID of the remote InfiniBand port associated with a
 * SCSI host by stripping prefix fe80:0000:0000:0000: from its GID. An
 * example: 0002:c903:00a0:5de2. Returns true on success, else false.
 */
static bool
get_srp_orig_dgid(const int h, char *b, int b_len)
{
        char buff[LMAX_DEVPATH];
        char value[LMAX_NAME];

        snprintf(buff, sizeof(buff), "%s%shost%d", sysfsroot, scsi_host_s, h);
        if (get_value(buff, odgi_s, value, sizeof(value)) &&
            strlen(value) > 20) {
                snprintf(b, b_len, "%s", value + 20);
                return true;
        }
        return false;
}

/*
 * Obtain the GUID of the remote InfiniBand port associated with a SCSI host
 * by stripping prefix fe80:0000:0000:0000: from its GID. An example:
 * 0002:c903:00a0:5de2. Returns true on success else false.
 */
static bool
get_srp_dgid(const int h, char *b, int b_len)
{
        char buff[LMAX_DEVPATH];
        char value[LMAX_NAME];

        snprintf(buff, sizeof(buff), "%s%shost%d", sysfsroot, scsi_host_s, h);
        if (get_value(buff, dgi_s, value, sizeof(value)) &&
            strlen(value) > 20) {
                snprintf(b, b_len, "%s", value + 20);
                return true;
        }
        return false;
}

/* Check host associated with 'devname' for known transport types. If so set
 * transport_id, place a string in 'b' and return true. Otherwise return
 * false. */
static bool
transport_init(const char * devname, int b_len, char * b)
{
        int off;
        char * cp;
        char buff[LMAX_DEVPATH];
        char wd[LMAX_PATH];
        struct stat a_stat;
        static const int bufflen = sizeof(buff);

        /* SPI host */
        snprintf(buff, bufflen, "%s%s%s", sysfsroot, spi_host_s, devname);
        if ((stat(buff, &a_stat) >= 0) && S_ISDIR(a_stat.st_mode)) {
                transport_id = TRANSPORT_SPI;
                snprintf(b, b_len, "spi:");
                return true;
        }

        /* FC host */
        snprintf(buff, bufflen, "%s/%s/%s/%s", sysfsroot, cl_s, fc_h_s,
                 devname);
        if ((stat(buff, &a_stat) >= 0) && S_ISDIR(a_stat.st_mode)) {
                if (get_value(buff, "symbolic_name", wd, sizeof(wd))) {
                        if (strstr(wd, " over ")) {
                                transport_id = TRANSPORT_FCOE;
                                snprintf(b, b_len, "fcoe:");
                        }
                }
                if (transport_id != TRANSPORT_FCOE) {
                        transport_id = TRANSPORT_FC;
                        snprintf(b, b_len, "fc:");
                }
                off = strlen(b);
                if (get_value(buff, ptn_s, b + off, b_len - off)) {
                        off = strlen(b);
                        my_strcopy(b + off, ",", b_len - off);
                        off = strlen(b);
                } else
                        return false;
                if (get_value(buff, "port_id", b + off, b_len - off))
                        return true;
                else
                        return false;
        }

        /* SRP host */
        snprintf(buff, bufflen, "%s%s%s", sysfsroot, srp_h_s, devname);
        if (stat(buff, &a_stat) >= 0 && S_ISDIR(a_stat.st_mode)) {
                int h;

                transport_id = TRANSPORT_SRP;
                snprintf(b, b_len, "srp:");
                if (sscanf(devname, "host%d", &h) == 1)
                        get_local_srp_gid(h, b + strlen(b), b_len - strlen(b));
                return true;
        }

        /* SAS host */
        /* SAS transport layer representation */
        snprintf(buff, bufflen, "%s%s%s", sysfsroot, sas_host_s, devname);
        if ((stat(buff, &a_stat) >= 0) && stat_is_dir_or_symlink(&a_stat)) {
                transport_id = TRANSPORT_SAS;
                snprintf(b, b_len, "sas:");
                off = strlen(buff);
                snprintf(buff + off, bufflen - off, "/device");
                if (sas_low_phy_scan(buff, NULL) < 1)
                        return false;
                snprintf(buff, bufflen, "%s%s%s", sysfsroot, sas_phy_s,
                         sas_low_phy);
                off = strlen(b);
                if (get_value(buff, sas_ad_s, b + off, b_len - off))
                        return true;
                else {
                        if (gl_verbose)
                                pr2serr("%s: no %s, wd=%s\n", __func__,
                                        sas_ad_s, buff);
                        return false;
                }
        }

        /* SAS class representation */
        snprintf(buff, bufflen, "%s%s%s%s", sysfsroot, scsi_host_s,
                 devname, "/device/sas/ha");
        if ((stat(buff, &a_stat) >= 0) && S_ISDIR(a_stat.st_mode)) {
                transport_id = TRANSPORT_SAS_CLASS;
                snprintf(b, b_len, "sas:");
                off = strlen(b);
                if (get_value(buff, dev_n_s, b + off, b_len - off))
                        return true;
                else {
                        if (gl_verbose)
                                pr2serr("%s: no %s, wd=%s\n",
                                        __func__, dev_n_s, buff);
                        return false;
                }
        }

        /* SBP (FireWire) host */
        do {
                char *t, buff2[LMAX_DEVPATH - 4];

                /* resolve SCSI host device */
                snprintf(buff, bufflen, "%s%s%s%s", sysfsroot, scsi_host_s,
                         devname, "/device");
                if (readlink(buff, buff2, sizeof(buff2)) <= 0)
                        break;

                /* check if the SCSI host has a FireWire host as ancestor */
                if (!(t = strstr(buff2, "/fw-host")))
                        break;
                transport_id = TRANSPORT_SBP;

                /* terminate buff2 after FireWire host */
                if (!(t = strchr(t+1, '/')))
                        break;
                *t = 0;

                /* resolve FireWire host device */
                buff[strlen(buff) - strlen(dvc_s)] = 0;
                if (strlen(buff) + strlen(buff2) + strlen("host_id/guid") + 2
                    > bufflen)
                        break;
                my_strcopy(buff + strlen(buff), buff2, bufflen);

                /* read the FireWire host's EUI-64 */
                if (!get_value(buff, "host_id/guid", buff2, sizeof(buff2)) ||
                    strlen(buff2) != 18)
                        break;
                snprintf(b, b_len, "sbp:%.120s", buff2 + 2);
                return true;
        } while (0);

        /* iSCSI host */
        snprintf(buff, bufflen, "%s%s%s", sysfsroot, iscsi_h_s, devname);
        if ((stat(buff, &a_stat) >= 0) && S_ISDIR(a_stat.st_mode)) {
                transport_id = TRANSPORT_ISCSI;
                snprintf(b, b_len, "iscsi:");
// >>>       Can anything useful be placed after "iscsi:" in single line
//           host output?
//           Hmmm, probably would like SAM-4 ",i,0x" notation here.
                return true;
        }

        /* USB host? */
        cp = get_usb_devname(devname, NULL, wd, sizeof(wd) - 1);
        if (cp) {
                transport_id = TRANSPORT_USB;
                snprintf(b, b_len, "usb:%s", cp);
                return true;
        }

        /* ATA or SATA host, crude check: driver name */
        snprintf(buff, bufflen, "%s%s%s", sysfsroot, scsi_host_s, devname);
        if (get_value(buff, "proc_name", wd, sizeof(wd))) {
                if (0 == strcmp("ahci", wd)) {
                        transport_id = TRANSPORT_SATA;
                        snprintf(b, b_len, "sata:");
                        return true;
                } else if (strstr(wd, "ata")) {
                        if (0 == memcmp("sata", wd, 4)) {
                                transport_id = TRANSPORT_SATA;
                                snprintf(b, b_len, "sata:");
                                return true;
                        }
                        transport_id = TRANSPORT_ATA;
                        snprintf(b, b_len, "ata:");
                        return true;
                }
        }
        return false;
}

/* Given the transport_id of a SCSI host (initiator) associated with
 * 'path_name' output additional information.
 */
static void
transport_init_longer(const char * path_name, struct lsscsi_opts * op,
                      sgj_opaque_p jop)
{
        int k, j, len, phynum, portnum;
        char * cp;
        sgj_state * jsp = &op->json_st;
        sgj_opaque_p jo2p = NULL;
        sgj_opaque_p jap = NULL;
        struct dirent ** phylist;
        struct dirent ** portlist;
        struct stat a_stat;
        char b[LMAX_PATH];
        char bname[LMAX_NAME];
        char value[LMAX_NAME];
        static const int blen = sizeof(b);
        static const int vlen = sizeof(value);
        /* If string used by another function, moved to file scope */
        static const char * sig_s = "signalling";
        static const char * afc4_s = "active_fc4s";
        static const char * sfc4_s = "supported_fc4s";
        static const char * fn_s = "fabric_name";
        static const char * mfs_s = "maxframe_size";
        static const char * mnp_s = "max_npiv_vports";
        static const char * nvi_s = "npiv_vports_inuse";
        static const char * ptt_s = "port_type";
        static const char * sp_s = "speed";
        static const char * ssp_s = "supported_speeds";
        static const char * tbt_s = "tgtid_bind_type";
        static const char * ha_n_s = "ha_name";
        static const char * vd_s = "version_descriptor";
        static const char * e_s = "enabled";
        static const char * om_s = "oob_mode";
        static const char * r_s = "role";
        static const char * ty_s = "type";

        my_strcopy(b, path_name, blen);
        cp = basename(b);
        my_strcopy(bname, cp, sizeof(bname));
        bname[sizeof(bname) - 1] = '\0';
        cp = bname;
        switch (transport_id) {
        case TRANSPORT_SPI:
                sgj_haj_vs(jsp, jop, 2, trans_s, SEP_EQ_NO_SP, "spi");
                snprintf(b, blen, "%s%s%s", sysfsroot, spi_host_s, cp);
                if (get_value(b, sig_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, sig_s, SEP_EQ_NO_SP, value);
                break;
        case TRANSPORT_FC:
        case TRANSPORT_FCOE:
                sgj_haj_vs(jsp, jop, 2, trans_s, SEP_EQ_NO_SP,
                           (transport_id == TRANSPORT_FC) ? "fc:" : "fcoe:");
                sg_scnpr(b, blen, "%s/%s/%s/%s", path_name, dvc_s, fc_h_s,
                         cp);
                if (stat(b, &a_stat) < 0) {
                        if (op->verbose > 2)
                                pr2serr("no %s directory\n", fc_h_s);
                        break;
                }
                if (get_value(b, afc4_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, afc4_s, SEP_EQ_NO_SP, value);
                if (get_value(b, sfc4_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, sfc4_s, SEP_EQ_NO_SP, value);
                if (get_value(b, fn_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, fn_s, SEP_EQ_NO_SP, value);
                if (get_value(b, mfs_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, mfs_s, SEP_EQ_NO_SP, value);
                if (get_value(b, mnp_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, mnp_s, SEP_EQ_NO_SP, value);
                if (get_value(b, nvi_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, nvi_s, SEP_EQ_NO_SP, value);
                if (get_value(b, ndn_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, ndn_s, SEP_EQ_NO_SP, value);
                if (get_value(b, ptn_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, ptn_s, SEP_EQ_NO_SP, value);
                if (get_value(b, pti_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, pti_s, SEP_EQ_NO_SP, value);
                if (get_value(b, pts_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, pts_s, SEP_EQ_NO_SP, value);
                if (get_value(b, ptt_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, ptt_s, SEP_EQ_NO_SP, value);
                if (get_value(b, sp_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, sp_s, SEP_EQ_NO_SP, value);
                if (get_value(b, ssp_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, ssp_s, SEP_EQ_NO_SP, value);
                if (get_value(b, scl_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, scl_s, SEP_EQ_NO_SP, value);
                if (get_value(b, tbt_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, tbt_s, SEP_EQ_NO_SP, value);
                if (op->verbose > 2)
                        pr2serr("%s: %s\n", ffd_s, b);
                break;
        case TRANSPORT_SRP:
                sgj_haj_vs(jsp, jop, 2, trans_s, SEP_EQ_NO_SP, "srp");
                {
                        int h;

                        if (sscanf(path_name, "host%d", &h) != 1)
                                break;
                        if (get_srp_orig_dgid(h, value, vlen))
                                sgj_haj_vs(jsp, jop, 2, odgi_s, SEP_EQ_NO_SP,
                                           value);
                        if (get_srp_dgid(h, value, vlen))
                                sgj_haj_vs(jsp, jop, 2, dgi_s, SEP_EQ_NO_SP,
                                           value);
                }
                break;
        case TRANSPORT_SAS:
                sgj_haj_vs(jsp, jop, 2, trans_s, SEP_EQ_NO_SP, "sas");
                snprintf(b, blen, "%s%s", path_name, "" /* was: "/device" */);
                if ((portnum = sas_port_scan(b, &portlist)) < 1) {
                        /* no configured ports */
                        sgj_pr_hr(jsp, "  no configured ports\n");
                        if ((phynum = sas_low_phy_scan(b, &phylist)) < 1) {
                                sgj_pr_hr(jsp, "  no configured phys\n");
                                return;
                        }
                        jap = sgj_named_subarray_r(jsp, jop, "phy_list");
                        for (k = 0; k < phynum; ++k) {
                                /* emit something potentially useful */
                                snprintf(b, blen, "%s%s%s", sysfsroot,
                                         sas_phy_s, phylist[k]->d_name);
                                sgj_pr_hr(jsp, "  %s\n", phylist[k]->d_name);
                                jo2p = sgj_new_unattached_object_r(jsp);
                                sgj_js_nv_s(jsp, jo2p, "phy_name",
                                            phylist[k]->d_name);
                                if (get_value(b, sas_ad_s, value, vlen))
                                        sgj_haj_vs(jsp, jo2p, 4, sas_ad_s,
                                                   SEP_EQ_NO_SP, value);
                                if (get_value(b, ph_id_s, value, vlen))
                                        sgj_haj_vs(jsp, jo2p, 4, ph_id_s,
                                                   SEP_EQ_NO_SP, value);
                                if (get_value(b, min_lr_s, value, vlen))
                                        sgj_haj_vs(jsp, jo2p, 4, min_lr_s,
                                                   SEP_EQ_NO_SP, value);
                                if (get_value(b, min_lrh_s, value, vlen))
                                        sgj_haj_vs(jsp, jo2p, 4, min_lrh_s,
                                                   SEP_EQ_NO_SP, value);
                                if (get_value(b, max_lr_s, value, vlen))
                                        sgj_haj_vs(jsp, jo2p, 4, max_lr_s,
                                                   SEP_EQ_NO_SP, value);
                                if (get_value(b, max_lrh_s, value, vlen))
                                        sgj_haj_vs(jsp, jo2p, 4, max_lrh_s,
                                                   SEP_EQ_NO_SP, value);
                                if (get_value(b, neg_lr_s, value, vlen))
                                        sgj_haj_vs(jsp, jo2p, 4, neg_lr_s,
                                                   SEP_EQ_NO_SP, value);
                                sgj_js_nv_o(jsp, jap, NULL, jo2p);
                        }
                        return;
                }
                jap = sgj_named_subarray_r(jsp, jop, "port_list");
                for (k = 0; k < portnum; ++k) {     /* for each host port */
                        int n = 0;
                        const char * pln = portlist[k]->d_name;
                        char b2[168];
                        static const int b2len = sizeof(b2);
                        static const char * dt_s = "device_type";
                        static const char * idc_s = "invalid_dword_count";
                        static const char * lodsc_s =
                                        "loss_of_dword_sync_count";
                        static const char * prpc_s =
                                        "phy_reset_problem_count";
                        static const char * rdec_s =
                                        "running_disparity_error_count";

                        sg_scnpr(b, blen, "%s%s%s", path_name, "/device/",
                                 pln);
                        if ((phynum = sas_low_phy_scan(b, &phylist)) < 1) {
                                sgj_pr_hr(jsp, "  %s: phy list not "
                                          "available\n", pln);
                                free(portlist[k]);
                                continue;
                        }
                        snprintf(b, blen, "%s%s%s", sysfsroot,
                                 "/class/sas_port/", pln);
                        if (get_value(b, "num_phys", value, vlen)) {
                                sgj_pr_hr(jsp, "  %s: num_phys=%s,", pln,
                                          value);
                                for (j = 0; j < phynum; ++j) {
                                        n += sg_scn3pr(b2, b2len, n, "  %s: "
                                                       "num_phys=%s,", pln,
                                                       value);
                                        free(phylist[j]);
                                }
                                sgj_pr_hr(jsp, "%s\n", b2);
                                if (op->verbose > 2)
                                        pr2serr("  %s: %s\n", ffd_s, b);
                                free(phylist);
                        }
                        jo2p = sgj_new_unattached_object_r(jsp);
                        snprintf(b, blen, "%s%s%s", sysfsroot, sas_phy_s,
                                 sas_low_phy);
                        if (get_value(b, dt_s, value, vlen))
                                sgj_haj_vs(jsp, jo2p, 4, dt_s, SEP_EQ_NO_SP,
                                           value);
                        if (get_value(b, ipp_s, value, vlen))
                                sgj_haj_vs(jsp, jo2p, 4, ipp_s, SEP_EQ_NO_SP,
                                           value);
                        if (get_value(b, idc_s, value, vlen))
                                sgj_haj_vs(jsp, jo2p, 4, idc_s, SEP_EQ_NO_SP,
                                           value);
                        if (get_value(b, lodsc_s, value, vlen))
                                sgj_haj_vs(jsp, jo2p, 4, lodsc_s,
                                           SEP_EQ_NO_SP, value);
                        if (get_value(b, min_lr_s, value, vlen))
                                sgj_haj_vs(jsp, jo2p, 4, min_lr_s,
                                           SEP_EQ_NO_SP, value);
                        if (get_value(b, min_lrh_s, value, vlen))
                                sgj_haj_vs(jsp, jo2p, 4, min_lrh_s,
                                           SEP_EQ_NO_SP, value);
                        if (get_value(b, max_lr_s, value, vlen))
                                sgj_haj_vs(jsp, jo2p, 4, max_lr_s,
                                           SEP_EQ_NO_SP, value);
                        if (get_value(b, max_lrh_s, value, vlen))
                                sgj_haj_vs(jsp, jo2p, 4, max_lrh_s,
                                           SEP_EQ_NO_SP, value);
                        if (get_value(b, neg_lr_s, value, vlen))
                                sgj_haj_vs(jsp, jo2p, 4, neg_lr_s,
                                           SEP_EQ_NO_SP, value);
                        if (get_value(b, ph_id_s, value, vlen))
                                sgj_haj_vs(jsp, jo2p, 4, ph_id_s,
                                           SEP_EQ_NO_SP, value);
                        if (get_value(b, prpc_s, value, vlen))
                                sgj_haj_vs(jsp, jo2p, 4, prpc_s,
                                           SEP_EQ_NO_SP, value);
                        if (get_value(b, rdec_s, value, vlen))
                                sgj_haj_vs(jsp, jo2p, 4, rdec_s,
                                           SEP_EQ_NO_SP, value);
                        if (get_value(b, sas_ad_s, value, vlen))
                                sgj_haj_vs(jsp, jo2p, 4, sas_ad_s,
                                           SEP_EQ_NO_SP, value);
                        if (get_value(b, tpp_s, value, vlen))
                                sgj_haj_vs(jsp, jo2p, 4, tpp_s,
                                           SEP_EQ_NO_SP, value);
                        if (op->verbose > 2)
                                pr2serr("  %s: %s\n", ffd_s, b);

                        free(portlist[k]);
                        sgj_js_nv_o(jsp, jap, NULL, jo2p);

                }
                free(portlist);

                break;
        case TRANSPORT_SAS_CLASS:
                sgj_haj_vs(jsp, jop, 2, trans_s, SEP_EQ_NO_SP, "sas");
                sgj_haj_vs(jsp, jop, 2, subtrans_s, SEP_EQ_NO_SP,
                           "sas_class");
                sg_scnpr(b, blen, "%s%s", path_name, "/device/sas/ha");
                if (get_value(b, dev_n_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, dev_n_s, SEP_EQ_NO_SP, value);
                if (get_value(b, ha_n_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, ha_n_s, SEP_EQ_NO_SP, value);
                if (get_value(b, vd_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, vd_s, SEP_EQ_NO_SP, value);
                jo2p = sgj_named_subobject_r(jsp, jop, "phy0");
                sgj_pr_hr(jsp, "  phy0:\n");
                len = strlen(b);
                snprintf(b + len, blen - len, "%s", "/phys/0");
                if (get_value(b, cl_s, value, vlen))
                        sgj_haj_vs(jsp, jo2p, 4, cl_s, SEP_EQ_NO_SP, value);
                if (get_value(b, e_s, value, vlen))
                        sgj_haj_vs(jsp, jo2p, 4, e_s, SEP_EQ_NO_SP, value);
                if (get_value(b, "id", value, vlen))
                        sgj_haj_vs(jsp, jo2p, 4, "id", SEP_EQ_NO_SP, value);
                if (get_value(b, ip_s, value, vlen))
                        sgj_haj_vs(jsp, jo2p, 4, ip_s, SEP_EQ_NO_SP, value);
                if (get_value(b, lr_s, value, vlen))
                        sgj_haj_vs(jsp, jo2p, 4, lr_s, SEP_EQ_NO_SP, value);
                if (get_value(b, om_s, value, vlen))
                        sgj_haj_vs(jsp, jo2p, 4, om_s, SEP_EQ_NO_SP, value);
                if (get_value(b, r_s, value, vlen))
                        sgj_haj_vs(jsp, jo2p, 4, r_s, SEP_EQ_NO_SP, value);
                if (get_value(b, sas_ad2_s, value, vlen))
                        sgj_haj_vs(jsp, jo2p, 4, sas_ad2_s, SEP_EQ_NO_SP,
                                   value);
                if (get_value(b, tp_s, value, vlen))
                        sgj_haj_vs(jsp, jo2p, 4, tp_s, SEP_EQ_NO_SP, value);
                if (get_value(b, ty_s, value, vlen))
                        sgj_haj_vs(jsp, jo2p, 4, ty_s, SEP_EQ_NO_SP, value);
                if (op->verbose > 2)
                        pr2serr("%s: %s\n", ffd_s, b);
                break;
        case TRANSPORT_ISCSI:
                sgj_haj_vs(jsp, jop, 2, trans_s, SEP_EQ_NO_SP, "iSCSI");
// >>>       This is the multi-line host output for iSCSI. Anymore to
//           add here? [From
//           /sys/class/scsi_host/hostN/device/iscsi_host:hostN directory]
                break;
        case TRANSPORT_SBP:
                sgj_haj_vs(jsp, jop, 2, trans_s, SEP_EQ_NO_SP, "sbp");
                break;
        case TRANSPORT_USB:
                sgj_haj_vs(jsp, jop, 2, trans_s, SEP_EQ_NO_SP, "usb");
                sgj_haj_vs(jsp, jo2p, 4, dev_n_s, SEP_EQ_NO_SP,
                           get_usb_devname(cp, NULL, value, vlen));
                break;
        case TRANSPORT_ATA:
                sgj_haj_vs(jsp, jop, 2, trans_s, SEP_EQ_NO_SP, "ata");
                break;
        case TRANSPORT_SATA:
                sgj_haj_vs(jsp, jop, 2, trans_s, SEP_EQ_NO_SP, "sata");
                break;
        case TRANSPORT_PCIE:
                sgj_haj_vs(jsp, jop, 2, trans_s, SEP_EQ_NO_SP, pcie_s);
                break;
        default:
                if (op->verbose > 1)
                        pr2serr("No %s information\n", trans_s);
                break;
        }
}

/* Attempt to determine the transport type of the SCSI device (LU) associated
 * with 'devname'. If found set transport_id, place string in 'b' and return
 * true. Otherwise return false. */
static bool
transport_tport(const char * devname, const struct lsscsi_opts * op,
                int b_len, char * b)
{
        bool ata_dev;
        int n, off, bufflen, wdlen;
        char * cp;
        char buff[LMAX_DEVPATH];
        char wd[LMAX_PATH];
        char nm[LMAX_NAME];
        char tpgt[LMAX_NAME];
        struct addr_hctl hctl;
        struct stat a_stat;

        if (! parse_colon_list(devname, &hctl))
                return false;

        bufflen = sizeof(buff);
        wdlen = sizeof(wd);
        /* check for SAS host */
        snprintf(buff, bufflen, "%s%shost%d", sysfsroot, sas_host_s, hctl.h);
        if ((stat(buff, &a_stat) >= 0) && stat_is_dir_or_symlink(&a_stat)) {
                /* SAS transport layer representation */
                transport_id = TRANSPORT_SAS;
                snprintf(buff, bufflen, "%s/%s/%s/%s", sysfsroot, cl_s,
                         sdev_s, devname);
                if (if_directory_chdir(buff, dvc_s)) {
                        if (NULL == getcwd(wd, wdlen))
                                return false;
                        cp = strrchr(wd, '/');
                        if (NULL == cp)
                                return false;
                        *cp = '\0';
                        cp = strrchr(wd, '/');
                        if (NULL == cp)
                                return false;
                        *cp = '\0';
                        cp = basename(wd);
                        my_strcopy(sas_hold_end_device, cp,
                                   sizeof(sas_hold_end_device));
                        snprintf(buff, bufflen, "%s/%s/%s/%s", sysfsroot,
                                 cl_s, sasdev_s, cp);

                        snprintf(b, b_len, "sas:");
                        off = strlen(b);
                        if (get_value(buff, sas_ad_s, b + off, b_len - off))
                                return true;
                        else {  /* non-SAS device in SAS domain */
                                snprintf(b + off, b_len - off,
                                         "0x0000000000000000");
                                if (op->verbose > 1)
                                        pr2serr("%s: no %s, wd=%s\n",
                                                 __func__, sas_ad_s, buff);
                                return true;
                        }
                } else
                        pr2serr("%s: down FAILED: %s\n", __func__, buff);
                return false;
        }

        /* not SAS, so check for SPI host */
        snprintf(buff, bufflen, "%s%shost%d", sysfsroot, spi_host_s, hctl.h);
        if ((stat(buff, &a_stat) >= 0) && S_ISDIR(a_stat.st_mode)) {
                transport_id = TRANSPORT_SPI;
                snprintf(b, b_len, "spi:%d", hctl.t);
                return true;
        }

        /* no, so check for FC host */
        snprintf(buff, bufflen, "%s/%s/%s/host%d", sysfsroot, cl_s, fc_h_s,
                 hctl.h);
        if ((stat(buff, &a_stat) >= 0) && S_ISDIR(a_stat.st_mode)) {
                if (get_value(buff, "symbolic_name", wd, wdlen)) {
                        if (strstr(wd, " over ")) {
                                transport_id = TRANSPORT_FCOE;
                                snprintf(b, b_len, "fcoe:");
                        }
                }
                if (transport_id != TRANSPORT_FCOE) {
                        transport_id = TRANSPORT_FC;
                        snprintf(b, b_len, "fc:");
                }
                snprintf(buff, bufflen, "%s%starget%d:%d:%d", sysfsroot,
                         "/class/fc_transport/", hctl.h, hctl.c, hctl.t);
                off = strlen(b);
                if (get_value(buff, ptn_s, b + off, b_len - off)) {
                        off = strlen(b);
                        my_strcopy(b + off, ",", b_len - off);
                        off = strlen(b);
                } else
                        return false;
                if (get_value(buff, "port_id", b + off, b_len - off))
                        return true;
                else
                        return false;
        }

        /* no, so check for SRP host */
        snprintf(buff, bufflen, "%s%shost%d", sysfsroot, srp_h_s, hctl.h);
        if (stat(buff, &a_stat) >= 0 && S_ISDIR(a_stat.st_mode)) {
                transport_id = TRANSPORT_SRP;
                snprintf(b, b_len, "srp:");
                get_local_srp_gid(hctl.h, b + strlen(b), b_len - strlen(b));
                return true;
        }

        /* SAS class representation or SBP? */
        snprintf(buff, bufflen, "%s%s/%s", sysfsroot, bus_scsi_dev_s,
                 devname);
        if (if_directory_chdir(buff, sasdev_s)) {
                transport_id = TRANSPORT_SAS_CLASS;
                snprintf(b, b_len, "sas:");
                off = strlen(b);
                if (get_value(".", sas_ad2_s, b + off, b_len - off))
                        return true;
                else
                        pr2serr("%s: no sas_addr, wd=%s\n", __func__, buff);
        } else if (get_value(buff, i1394id_s, wd, wdlen)) {
                /* IEEE1394 SBP device */
                transport_id = TRANSPORT_SBP;
                n = 0;
                n += sg_scn3pr(b, b_len, n, "%s", "sbp:");
                sg_scn3pr(b, b_len, n, "%s:", wd);
                return true;
        }

        /* iSCSI device? */
        snprintf(buff, bufflen, "%s%shost%d/device", sysfsroot, iscsi_h_s,
                 hctl.h);
        if ((stat(buff, &a_stat) >= 0) && S_ISDIR(a_stat.st_mode)) {
                if (1 != iscsi_target_scan(buff, &hctl))
                        return false;
                transport_id = TRANSPORT_ISCSI;
                snprintf(buff, bufflen, "%s%ssession%d", sysfsroot,
                         iscsi_sess_s, iscsi_tsession_num);
                if (! get_value(buff, tgtn_s, nm, sizeof(nm)))
                        return false;
                if (! get_value(buff, tpgt_s, tpgt, sizeof(tpgt)))
                        return false;
                // output target port name as per sam4r08, annex A, table A.3
                n = 0;
                n += sg_scn3pr(b, b_len, n, "%s", nm);
                sg_scn3pr(b, b_len, n, ",t,0x%x", (uint32_t)atoi(tpgt));
// >>>       That reference says maximum length of targetname is 223 bytes
//           (UTF-8) excluding trailing null.
                return true;
        }

        /* USB device? */
        cp = get_usb_devname(NULL, devname, wd, wdlen - 1);
        if (cp) {
                transport_id = TRANSPORT_USB;
                snprintf(b, b_len, "usb:%s", cp);
                return true;
        }

        /* ATA or SATA device, crude check: driver name */
        snprintf(buff, bufflen, "%s%shost%d", sysfsroot, scsi_host_s, hctl.h);
        if (get_value(buff, "proc_name", wd, wdlen)) {
                ata_dev = false;
                if (0 == strcmp("ahci", wd)) {
                        transport_id = TRANSPORT_SATA;
                        snprintf(b, b_len, "sata:");
                        ata_dev = true;
                } else if (strstr(wd, "ata")) {
                        if (0 == memcmp("sata", wd, 4)) {
                                transport_id = TRANSPORT_SATA;
                                snprintf(b, b_len, "sata:");
                        } else {
                                transport_id = TRANSPORT_ATA;
                                snprintf(b, b_len, "ata:");
                        }
                        ata_dev = true;
                }
                if (ata_dev) {
                        off = strlen(b);
                        sg_scn3pr(b, b_len, off, "%s",
                                  get_lu_name(devname, wd, wdlen, false));
                        return true;
                }
        }
        return false;
}

/* Given the transport_id of the SCSI device (LU) associated with 'devname'
 * output additional information. */
static void
transport_tport_longer(const char * devname, struct lsscsi_opts * op,
                       sgj_opaque_p jop)
{
        int n;
        char * cp;
        sgj_state * jsp = &op->json_st;
        sgj_opaque_p jo2p = NULL;
        char path_name[LMAX_DEVPATH];
        char buff[LMAX_DEVPATH];
        char b2[LMAX_DEVPATH];
        char wd[LMAX_PATH];
        char value[LMAX_NAME];
        struct addr_hctl hctl;
        static const int bufflen = sizeof(buff);
        static const int b2len = sizeof(b2);
        static const int vlen = sizeof(value);
        static const int wdlen = sizeof(wd);
        /* If string used by another function, moved to file scope */
        static const char * dt_s = "dt";
        static const char * mo_s = "max_offset";
        static const char * mw_s = "max_width";
        static const char * mp_s = "min_period";
        static const char * of_s = "offset";
        static const char * pe_s = "period";
        static const char * wi_s = "width";
        static const char * ro_s = "roles";
        static const char * fif_s = "fast_io_fail_tmo";
        static const char * dlt_s = "dev_loss_tmo";
        static const char * bid_s = "bay_identifier";
        static const char * eid_s = "enclosure_identifier";
        static const char * irt_s = "initiator_response_timeout";
        static const char * itnlt_s = "I_T_nexus_loss_timeout";
        static const char * rlm_s = "ready_led_meaning";
        static const char * tlr_e_s = "tlr_enabled";
        static const char * tlr_s_s = "tlr_supported";
        static const char * devt_s = "dev_type";
        static const char * irt2_s = "iresp_timeout";
        static const char * itnlt2_s = "itnl_timeout";
        static const char * mlr_s = "max_linkrate";
        static const char * mpw_s = "max_pathways";
        static const char * milr_s = "min_linkrate";
        static const char * pw_s = "pathways";
        static const char * rl_wlun_s = "rl_wlun";
        static const char * tlr_s = "transport_layer_retries";
        static const char * dpio_s = "data_pdu_in_order";
        static const char * dsio_s = "data_seq_in_order";
        static const char * erl_s = "erl";
        static const char * fbl_s = "first_burst_len";
        static const char * ir2t_s = "initial_r2t";
        static const char * mbl_s = "max_burst_len";
        static const char * mor2t_s = "max_outstanding_r2t";
        static const char * rtmo_s = "recovery_tmo";

#if 0
        snprintf(buff, bufflen, "%s/scsi_device:%s", path_name, devname);
        if (! if_directory_chdir(buff, "device"))
                return;
        if (NULL == getcwd(wd, wdlen))
                return;
#else
        snprintf(path_name, sizeof(path_name), "%s/%s/%s/%s", sysfsroot,
                 cl_s, sdev_s, devname);
        my_strcopy(buff, path_name, bufflen);
#endif
        switch (transport_id) {
        case TRANSPORT_SPI:
                sgj_haj_vs(jsp, jop, 2, trans_s, SEP_EQ_NO_SP, "spi");
                if (! parse_colon_list(devname, &hctl))
                        break;
                snprintf(buff, bufflen, "%s%starget%d:%d:%d", sysfsroot,
                        "/class/spi_transport/", hctl.h, hctl.c, hctl.t);
                sgj_haj_vi(jsp, jop, 2, "target_id", SEP_EQ_NO_SP, hctl.t,
                           false);
                if (get_value(buff, dt_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, dt_s, SEP_EQ_NO_SP, value);
                if (get_value(buff, mo_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, mo_s, SEP_EQ_NO_SP, value);
                if (get_value(buff, mw_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, mw_s, SEP_EQ_NO_SP, value);
                if (get_value(buff, mp_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, mp_s, SEP_EQ_NO_SP, value);
                if (get_value(buff, of_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, of_s, SEP_EQ_NO_SP, value);
                if (get_value(buff, pe_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, pe_s, SEP_EQ_NO_SP, value);
                if (get_value(buff, wi_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, wi_s, SEP_EQ_NO_SP, value);
                break;
        case TRANSPORT_FC:
        case TRANSPORT_FCOE:
                sgj_haj_vs(jsp, jop, 2, trans_s, SEP_EQ_NO_SP,
                           transport_id == TRANSPORT_FC ? "fc:" : "fcoe:");
                if (! if_directory_chdir(path_name, dvc_s))
                        return;
                if (NULL == getcwd(wd, wdlen))
                        return;
                cp = strrchr(wd, '/');
                if (NULL == cp)
                        return;
                *cp = '\0';
                cp = strrchr(wd, '/');
                if (NULL == cp)
                        return;
                *cp = '\0';
                cp = basename(wd);
                snprintf(buff, bufflen, "%s/%s", fc_rem_pts_s, cp);
                if (if_directory_chdir(wd, buff)) {
                        if (NULL == getcwd(buff, bufflen))
                                return;
                } else {  /* newer transport */
                        /* /sys  /class/fc_remote_ports/  rport-x:y-z  / */
                        snprintf(buff, bufflen, "%s/%s/%s/%s/", sysfsroot,
                                 cl_s, fc_rem_pts_s, cp);
                }
                n = 0;
                n += sg_scn3pr(b2, b2len, n, "%s", path_name);
                sg_scn3pr(b2, b2len, n, "%s", "/device/");
                if (get_value(b2, vend_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, vend_s, SEP_EQ_NO_SP, value);
                if (get_value(b2, model_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, model_s, SEP_EQ_NO_SP, value);
                sgj_pr_hr(jsp, "  %s\n", cp);    /* rport */
                jo2p = sgj_named_subobject_r(jsp, jop, cp);
                if (get_value(buff, ndn_s, value, vlen))
                        sgj_haj_vs(jsp, jo2p, 2, ndn_s, SEP_EQ_NO_SP, value);
                if (get_value(buff, ptn_s, value, vlen))
                        sgj_haj_vs(jsp, jo2p, 2, ptn_s, SEP_EQ_NO_SP, value);
                if (get_value(buff, pti_s, value, vlen))
                        sgj_haj_vs(jsp, jo2p, 2, pti_s, SEP_EQ_NO_SP, value);
                if (get_value(buff, pts_s, value, vlen))
                        sgj_haj_vs(jsp, jo2p, 2, pts_s, SEP_EQ_NO_SP, value);
                if (get_value(buff, ro_s, value, vlen))
                        sgj_haj_vs(jsp, jo2p, 2, ro_s, SEP_EQ_NO_SP, value);
// xxxxxxxxxxxx  following call to print_enclosure_device fails since b2 is
// inappropriate, comment out since might be useless (check with FCP folks)
                // print_enclosure_device(devname, b2, op);
                if (get_value(buff, sti_s, value, vlen))
                        sgj_haj_vs(jsp, jo2p, 2, sti_s, SEP_EQ_NO_SP, value);
                if (get_value(buff, scl_s, value, vlen))
                        sgj_haj_vs(jsp, jo2p, 2, scl_s, SEP_EQ_NO_SP, value);
                if (get_value(buff, fif_s, value, vlen))
                        sgj_haj_vs(jsp, jo2p, 2, fif_s, SEP_EQ_NO_SP, value);
                if (get_value(buff, dlt_s, value, vlen))
                        sgj_haj_vs(jsp, jo2p, 2, dlt_s, SEP_EQ_NO_SP, value);
                if (op->verbose > 2) {
                        pr2serr("  %s: %s\n", ffd_s, buff);
                        pr2serr("  %s: %s\n", ffd_s, b2);
                }
                break;
        case TRANSPORT_SRP:
                sgj_haj_vs(jsp, jop, 2, trans_s, SEP_EQ_NO_SP, "srp");
                if (! parse_colon_list(devname, &hctl))
                        break;
                if (get_srp_orig_dgid(hctl.h, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, odgi_s, SEP_EQ_NO_SP, value);
                if (get_srp_dgid(hctl.h, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, dgi_s, SEP_EQ_NO_SP, value);
                break;
        case TRANSPORT_SAS:
                sgj_haj_vs(jsp, jop, 2, trans_s, SEP_EQ_NO_SP, "sas");
                n = sg_scn3pr(b2, b2len, 0, "%s/%s/%s", sysfsroot, cl_s,
                              sasdev_s);
                sg_scn3pr(b2, b2len, n, "%s", sas_hold_end_device);
                if (get_value(b2, bid_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, bid_s, SEP_EQ_NO_SP, value);
                if (get_value(b2, eid_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, eid_s, SEP_EQ_NO_SP, value);
                if (get_value(b2, ipp_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, ipp_s, SEP_EQ_NO_SP, value);
                if (get_value(b2, ph_id_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, ph_id_s, SEP_EQ_NO_SP, value);
                if (get_value(b2, sas_ad_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, sas_ad_s, SEP_EQ_NO_SP,
                                   value);
                if (get_value(b2, sti_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, sti_s, SEP_EQ_NO_SP, value);
                if (get_value(b2, tpp_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, tpp_s, SEP_EQ_NO_SP, value);
                if (op->verbose > 2)
                        pr2serr("%s: %s\n", ffd_s, b2);
                n = 0;
                n += sg_scn3pr(b2, b2len, n, "%s", path_name);
                sg_scn3pr(b2, b2len, n, "%s", "/device/");
                if (get_value(b2, vend_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, vend_s, SEP_EQ_NO_SP, value);
                if (get_value(b2, model_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, model_s, SEP_EQ_NO_SP, value);
                n = 0;
                n += sg_scn3pr(b2, b2len, n, "%s", sysfsroot);
                n += sg_scn3pr(b2, b2len, n, "%s", "/class/sas_end_device/");
                sg_scn3pr(b2, b2len, n, "%s", sas_hold_end_device);
                print_enclosure_device(devname, b2, op);
                if (get_value(b2, irt_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, irt_s, SEP_EQ_NO_SP, value);
                if (get_value(b2, itnlt_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, itnlt_s, SEP_EQ_NO_SP, value);
                if (get_value(b2, rlm_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, rlm_s, SEP_EQ_NO_SP, value);
                if (get_value(b2, tlr_e_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, tlr_e_s, SEP_EQ_NO_SP, value);
                if (get_value(b2, tlr_s_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, tlr_s_s, SEP_EQ_NO_SP, value);
                if (op->verbose > 2)
                        pr2serr("%s: %s\n", ffd_s, b2);
                break;
        case TRANSPORT_SAS_CLASS:
                sgj_haj_vs(jsp, jop, 2, trans_s, SEP_EQ_NO_SP, "sas");
                sgj_haj_vs(jsp, jop, 2, subtrans_s, SEP_EQ_NO_SP,
                           "sas_class");
                n = 0;
                n += sg_scn3pr(buff, bufflen, n, "%s", path_name);
                sg_scn3pr(buff, bufflen, n, "/%s/%s", dvc_s, sasdev_s);
                if (get_value(buff, dev_n_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, dev_n_s, SEP_EQ_NO_SP, value);
                if (get_value(buff, devt_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, devt_s, SEP_EQ_NO_SP, value);
                if (get_value(buff, ip_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, ip_s, SEP_EQ_NO_SP, value);
                if (get_value(buff, irt2_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, irt2_s, SEP_EQ_NO_SP, value);
                if (get_value(buff, itnlt2_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, itnlt2_s, SEP_EQ_NO_SP, value);
                if (get_value(buff, lr_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, lr_s, SEP_EQ_NO_SP, value);
                if (get_value(buff, mlr_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, mlr_s, SEP_EQ_NO_SP, value);
                if (get_value(buff, mpw_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, mpw_s, SEP_EQ_NO_SP, value);
                if (get_value(buff, milr_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, milr_s, SEP_EQ_NO_SP, value);
                if (get_value(buff, pw_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, pw_s, SEP_EQ_NO_SP, value);
                if (get_value(buff, rlm_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, rlm_s, SEP_EQ_NO_SP, value);
                if (get_value(buff, rl_wlun_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, rl_wlun_s, SEP_EQ_NO_SP,
                                   value);
                if (get_value(buff, sas_ad2_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, sas_ad2_s, SEP_EQ_NO_SP,
                                   value);
                if (get_value(buff, tp_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, tp_s, SEP_EQ_NO_SP, value);
                if (get_value(buff, tlr_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, tlr_s, SEP_EQ_NO_SP, value);
                if (op->verbose > 2)
                        pr2serr("%s: %s\n", ffd_s, buff);
                break;
        case TRANSPORT_ISCSI:
                sgj_haj_vs(jsp, jop, 2, trans_s, SEP_EQ_NO_SP, "iSCSI");
                n = 0;
                n += sg_scn3pr(buff, bufflen, n, "%s", sysfsroot);
                n += sg_scn3pr(buff, bufflen, n, "%s", iscsi_sess_s);
                n += sg_scn3pr(buff, bufflen, n, "%s", "session");
                sg_scn3pr(buff, bufflen, n, "%d", iscsi_tsession_num);
                if (get_value(buff, tgtn_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, tgtn_s, SEP_EQ_NO_SP, value);
                if (get_value(buff, tpgt_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, tpgt_s, SEP_EQ_NO_SP, value);
                if (get_value(buff, dpio_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, dpio_s, SEP_EQ_NO_SP, value);
                if (get_value(buff, dsio_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, dsio_s, SEP_EQ_NO_SP, value);
                if (get_value(buff, erl_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, erl_s, SEP_EQ_NO_SP, value);
                if (get_value(buff, fbl_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, fbl_s, SEP_EQ_NO_SP, value);
                if (get_value(buff, ir2t_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, ir2t_s, SEP_EQ_NO_SP, value);
                if (get_value(buff, mbl_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, mbl_s, SEP_EQ_NO_SP, value);
                if (get_value(buff, mor2t_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, mor2t_s, SEP_EQ_NO_SP, value);
                if (get_value(buff, rtmo_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, rtmo_s, SEP_EQ_NO_SP, value);
// >>>       Would like to see what are readable attributes in this directory.
//           Ignoring connections for the time being. Could add with an entry
//           for connection=<n> with normal two space indent followed by
//           attributes for that connection indented 4 spaces
                if (op->verbose > 2)
                        pr2serr("%s: %s\n", ffd_s, buff);
                break;
        case TRANSPORT_SBP:
                sgj_haj_vs(jsp, jop, 2, trans_s, SEP_EQ_NO_SP, "sbp");
                if (! if_directory_chdir(path_name, dvc_s))
                        return;
                if (NULL == getcwd(wd, wdlen))
                        return;
                if (get_value(wd, i1394id_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, i1394id_s, SEP_EQ_NO_SP,
                                   value);
                if (op->verbose > 2)
                        pr2serr("%s: %s\n", ffd_s, buff);
                break;
        case TRANSPORT_USB:
                sgj_haj_vs(jsp, jop, 2, trans_s, SEP_EQ_NO_SP, "usb");
                sgj_haj_vs(jsp, jop, 2, dev_n_s, SEP_EQ_NO_SP,
                           get_usb_devname(NULL, devname, value, vlen));
                break;
        case TRANSPORT_ATA:
                sgj_haj_vs(jsp, jop, 2, trans_s, SEP_EQ_NO_SP, "ata");
                cp = get_lu_name(devname, b2, b2len, false);
                if (strlen(cp) > 0)
                        sgj_haj_vs(jsp, jop, 2, wwn_s, SEP_EQ_NO_SP, cp);
                break;
        case TRANSPORT_SATA:
                sgj_haj_vs(jsp, jop, 2, trans_s, SEP_EQ_NO_SP, "sata");
                cp = get_lu_name(devname, b2, b2len, false);
                if (strlen(cp) > 0)
                        sgj_haj_vs(jsp, jop, 2, wwn_s, SEP_EQ_NO_SP, cp);
                break;
        default:
                if (op->verbose > 1)
                        pr2serr("No %s information\n", trans_s);
                break;
        }
}

static int
rend_prot_protmode(const char * rb, char * o, int omlen, bool one_ln,
                   const char * leadin, struct lsscsi_opts * op,
                   sgj_opaque_p jop)
{
        bool as_json;
        bool sing = (op->long_opt > 2);
        int q = 0;
        const char * sep = NULL;
        sgj_state * jsp = &op->json_st;
        sgj_opaque_p jo2p = NULL;
        char value[LMAX_NAME];
        char sddir[LMAX_DEVPATH];
        char blkdir[LMAX_DEVPATH];
        static const int vlen = sizeof(value);
        static const char * ato_s = "app_tag_own";
        static const char * prott_s = "protection_type";
        static const char * form_s = "format";
        static const char * tgsz_s = "tag_size";
        static const char * protm_s = "protection_mode";

        as_json = jsp->pr_as_json;
        if (! one_ln)
                sep = sing ? "\n" : "";

        if (op->protection) {
                my_strcopy(sddir,  rb, sizeof(sddir));
                my_strcopy(blkdir, rb, sizeof(blkdir));

                jo2p = sgj_named_subobject_r(jsp, jop, "protection");
                if (sd_scan(sddir) &&
                    if_directory_chdir(sddir, ".") &&
                    get_value(".", prott_s, value, vlen)) {

                        if (one_ln) {
                                if (!strncmp(value, "0", 1))
                                        q += sg_scn3pr(o, omlen, q, "  %-9s",
                                                       "-");
                                else
                                        q += sg_scn3pr(o, omlen, q,
                                                       "  DIF/Type%1s",
                                                       value);
                        } else {
                                q += sg_scn3pr(o, omlen, q, "%s%s=%s%s",
                                               leadin, prott_s, value, sep);
                        }
                        if (as_json)
                                sgj_js_nv_s(jsp, jo2p, prott_s, value);
                        if (get_value(".", ato_s, value, vlen)) {
                                if (as_json)
                                        sgj_js_nv_s(jsp, jo2p, ato_s, value);
                                else if (! one_ln)
                                        q += sg_scn3pr(o, omlen, q,
                                                       "%s%s=%s%s", leadin,
                                                       ato_s, value, sep);
                        }
                } else
                        q += sg_scn3pr(o, omlen, q, "  %-9s", "-");

                if (block_scan(blkdir) &&
                    if_directory_chdir(blkdir, "integrity")) {
                        if (get_value(".", form_s, value, vlen)) {
                                if (one_ln)
                                        q += sg_scn3pr(o, omlen, q, "  %-16s",
                                                       value);
                                else
                                        q += sg_scn3pr(o, omlen, q,
                                                       "%s%s=%s%s", leadin,
                                                       form_s, value, sep);
                                if (as_json)
                                        sgj_js_nv_s(jsp, jo2p, form_s, value);
                        }
                        if (get_value(".", tgsz_s, value, vlen)) {
                                if (as_json)
                                        sgj_js_nv_s(jsp, jo2p, tgsz_s, value);
                                else if (! one_ln)
                                        q += sg_scn3pr(o, omlen, q,
                                                       "%s%s=%s%s", leadin,
                                                       tgsz_s, value, sep);
                        }
                } else
                        q += sg_scn3pr(o, omlen, q, "  %-16s", "-");
        }
        if (op->protmode) {
                my_strcopy(sddir, rb, sizeof(sddir));

                if (sd_scan(sddir) && if_directory_chdir(sddir, ".") &&
                    get_value(sddir, protm_s, value, vlen)) {

                        if (one_ln) {
                                if (0 == strcmp(value, none_s))
                                        q += sg_scn3pr(o, omlen, q, "  %-4s",
                                                       "-");
                                else
                                        q += sg_scn3pr(o, omlen, q, "  %-4s",
                                                       value);
                        } else {
                                q += sg_scn3pr(o, omlen, q, "%s%s=%s%s",
                                               leadin, protm_s, value, sep);
                        }
                        if (as_json)
                                sgj_js_nv_s(jsp, jop, protm_s, value);
                } else
                        q += sg_scn3pr(o, omlen, q, "  %-4s", "-");
        }
        return q;
}

static void
longer_sdev_entry(const char * path_name, const char * devname,
                  struct lsscsi_opts * op, sgj_opaque_p jop)
{
        int q = 0;
        sgj_state * jsp = &op->json_st;
        char value[LMAX_NAME];
        char b[256];
        static const int vlen = sizeof(value);
        static const int blen = sizeof(b);
        /* If string used by another function, moved to file scope */
        static const char * db_s = "device_blocked";
        static const char * dhs_s = "dh_state";
        static const char * iocb_s = "iocounterbits";
        static const char * iodc_s = "iodone_cnt";
        static const char * ioec_s = "ioerr_cnt";
        static const char * iorc_s = "iorequest_cnt";
        static const char * qd_s = "queue_depth";
        static const char * qt_s = "queue_type";
        static const char * sl_s = "scsi_level";
        static const char * tm_s = "timeout";
        static const char * ty_s = "type";

        if (op->transport_info) {
                transport_tport_longer(devname, op, jop);
                return;
        }
        if (op->long_opt >= 3) {
                if (get_value(path_name, db_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, db_s, SEP_EQ_NO_SP, value);
                else if (op->verbose > 0)
                        sgj_pr_hr(jsp, "  %s=?\n", db_s);
                if (get_value(path_name, dhs_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, dhs_s, SEP_EQ_NO_SP, value);
                if (get_value(path_name, iocb_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, iocb_s, SEP_EQ_NO_SP, value);
                else if (op->verbose > 0)
                        sgj_pr_hr(jsp, "  %s=?\n", iocb_s);
                if (get_value(path_name, iodc_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, iodc_s, SEP_EQ_NO_SP, value);
                else if (op->verbose > 0)
                        sgj_pr_hr(jsp, "  %s=?\n", iodc_s);
                if (get_value(path_name, ioec_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, ioec_s, SEP_EQ_NO_SP, value);
                else if (op->verbose > 0)
                        sgj_pr_hr(jsp, "  %s=?\n", ioec_s);
                if (get_value(path_name, iorc_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, iorc_s, SEP_EQ_NO_SP, value);
                else if (op->verbose > 0)
                        sgj_pr_hr(jsp, "  %s=?\n", iorc_s);
                if (get_value(path_name, qd_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, qd_s, SEP_EQ_NO_SP, value);
                else if (op->verbose > 0)
                        sgj_pr_hr(jsp, "  %s=?\n", qd_s);
                if (get_value(path_name, qt_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, qt_s, SEP_EQ_NO_SP, value);
                else if (op->verbose > 0)
                        sgj_pr_hr(jsp, "  %s=?\n", qt_s);
                if (get_value(path_name, sl_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, sl_s, SEP_EQ_NO_SP, value);
                else if (op->verbose > 0)
                        sgj_pr_hr(jsp, "  %s=?\n", sl_s);
                if (get_value(path_name, stat_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, stat_s, SEP_EQ_NO_SP, value);
                else if (op->verbose > 0)
                        sgj_pr_hr(jsp, "  %s=?\n", stat_s);
                if (get_value(path_name, tm_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, tm_s, SEP_EQ_NO_SP, value);
                else if (op->verbose > 0)
                        sgj_pr_hr(jsp, "  %s=?\n", tm_s);
                if (get_value(path_name, ty_s, value, vlen)) {
                        int pdt = -1;
                        const char * pdt_s = "? ?";

                        if ((1 == sscanf(value, "%d", &pdt)) &&
                            (pdt >= 0) && (pdt < 32))
                                pdt_s = scsi_device_types[pdt];
                        sgj_haj_vistr_nex(jsp, jop, 2, ty_s, SEP_EQ_NO_SP,
                                          pdt, true, pdt_s,
                                          "Peripheral Device Type (PDT)");
                        sgj_haj_vs(jsp, jop, 2, ty_s, SEP_EQ_NO_SP, value);
                } else if (op->verbose > 0)
                        sgj_pr_hr(jsp, "  %s=?\n", ty_s);
                if (get_value(path_name, uniqi_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, uniqi_s, SEP_EQ_NO_SP, value);
                rend_prot_protmode(path_name, b, blen, false, "  ", op, jop);
                sgj_pr_hr(jsp, "%s", b);
                return;
        }

        if (get_value(path_name, stat_s, value, vlen)) {
                q += sg_scn3pr(b, blen, q, " %s=%s", stat_s, value);
                sgj_js_nv_s(jsp, jop, stat_s, value);
        } else
                q += sg_scn3pr(b, blen, q, "  %s=?", stat_s);
        if (get_value(path_name, qd_s, value, vlen)) {
                q += sg_scn3pr(b, blen, q, " %s=%s", qd_s, value);
                sgj_js_nv_s(jsp, jop, qd_s, value);
        } else
                q += sg_scn3pr(b, blen, q, " %s=?", qd_s);
        if (get_value(path_name, sl_s, value, vlen)) {
                q += sg_scn3pr(b, blen, q, " %s=%s", sl_s, value);
                sgj_js_nv_s(jsp, jop, sl_s, value);
        } else
                q += sg_scn3pr(b, blen, q, " %s=?", sl_s);
        if (get_value(path_name, ty_s, value, vlen)) {
                q += sg_scn3pr(b, blen, q, " %s=%s", ty_s, value);
                sgj_js_nv_s(jsp, jop, ty_s, value);
        } else
                q += sg_scn3pr(b, blen, q, " %s=?", ty_s);
        if (get_value(path_name, db_s, value, vlen)) {
                q += sg_scn3pr(b, blen, q, " %s=%s", db_s, value);
                sgj_js_nv_s(jsp, jop, db_s, value);
        } else
                q += sg_scn3pr(b, blen, q, " %s=?", db_s);
        if (get_value(path_name, tm_s, value, vlen)) {
                /* q += */ sg_scn3pr(b, blen, q, " %s=%s", tm_s, value);
                sgj_js_nv_s(jsp, jop, tm_s, value);
        } else
                /* q += */ sg_scn3pr(b, blen, q, " %s=?", tm_s);
        if (op->long_opt == 2) {
                sgj_pr_hr(jsp, " %s\n", b);
                q = 0;
                if (get_value(path_name, iocb_s, value, vlen)) {
                        q += sg_scn3pr(b, blen, q, "  %s=%s", iocb_s, value);
                        sgj_js_nv_s(jsp, jop, iocb_s, value);
                } else if (op->verbose > 0)
                        q += sg_scn3pr(b, blen, q, "  %s=?\n", iocb_s);
                if (get_value(path_name, iodc_s, value, vlen)) {
                        q += sg_scn3pr(b, blen, q, " %s=%s", iodc_s, value);
                        sgj_js_nv_s(jsp, jop, iodc_s, value);
                } else
                        q += sg_scn3pr(b, blen, q, " %s=?", iodc_s);
                if (get_value(path_name, ioec_s, value, vlen)) {
                        q += sg_scn3pr(b, blen, q, " %s=%s", ioec_s, value);
                        sgj_js_nv_s(jsp, jop, ioec_s, value);
                } else
                        q += sg_scn3pr(b, blen, q, " %s=%s", ioec_s, value);
                if (get_value(path_name, iorc_s, value, vlen)) {
                        /* q += */ sg_scn3pr(b, blen, q, " %s=%s", iorc_s,
                                          value);
                        sgj_js_nv_s(jsp, jop, iorc_s, value);
                } else
                        /* q += */ sg_scn3pr(b, blen, q, " %s=%s", iorc_s,
                                          value);
                sgj_pr_hr(jsp, " %s\n", b);
                if (get_value(path_name, qt_s, value, vlen)) {
                        sg_scn3pr(b, blen, 0, " %s=%s", qt_s, value);
                        sgj_js_nv_s(jsp, jop, qt_s, value);
                } else
                        sg_scn3pr(b, blen, 0, " %s=%s", qt_s, value);
        }
        sgj_pr_hr(jsp, "  %s\n", b);
        if (op->protection || op->protmode) {
                rend_prot_protmode(path_name, b, blen, false, " ", op, jop);
                sgj_pr_hr(jsp, "  %s\n", b);
        }
}

#if (HAVE_NVME && (! IGNORE_NVME))

/* NVMe longer data for namespace listing */
static void
longer_nd_entry(const char * path_name, const char * devname,
                struct lsscsi_opts * op, sgj_opaque_p jop)
{
        sgj_state * jsp = &op->json_st;
        char value[LMAX_NAME];
        char b[LMAX_NAME];
        static const int vlen = sizeof(value);
        static const int blen = sizeof(b);
        static const char * cap_s = "capability";
        static const char * er_s = "ext_range";
        static const char * hi_s = "hidden";
        static const char * ra_s = "range";
        static const char * rem_s = "removable";
        static const char * nrq_s = "nr_requests";
        static const char * rakb_s = "read_ahead_kb";
        static const char * wc_s = "write_cache";

        if (devname) { ; }      /* suppress warning */
        if (op->long_opt) {
                int n = 0;
                bool as_json = jsp->pr_as_json;
                bool sing = (op->long_opt > 2);
                const char * sep = sing ? "\n" : "";

                if (get_value(path_name, cap_s, value, vlen)) {
                        if (as_json)
                                sgj_js_nv_s(jsp, jop, cap_s, value);
                        n += sg_scn3pr(b, blen, n, "  %s=%s%s", cap_s, value,
                                       sep);
                } else
                        n += sg_scn3pr(b, blen, n, "  %s=?%s", cap_s, sep);
                if (get_value(path_name, er_s, value, vlen)) {
                        if (as_json)
                                sgj_js_nv_s(jsp, jop, er_s, value);
                        n += sg_scn3pr(b, blen, n, "  %s=%s%s", er_s, value,
                                       sep);
                } else
                        n += sg_scn3pr(b, blen, n, "  %s=?%s", er_s, sep);
                if (get_value(path_name, hi_s, value, vlen)) {
                        if (as_json)
                                sgj_js_nv_s(jsp, jop, hi_s, value);
                        n += sg_scn3pr(b, blen, n, "  %s=%s%s", hi_s, value,
                                       sep);
                } else
                        n += sg_scn3pr(b, blen, n, "  %s=?%s", hi_s, sep);
                if (get_value(path_name, nsid_s, value, vlen)) {
                        if (as_json)
                                sgj_js_nv_s(jsp, jop, nsid_s, value);
                        n += sg_scn3pr(b, blen, n, "  %s=%s%s", nsid_s, value,
                                       sep);
                } else
                        n += sg_scn3pr(b, blen, n, "  %s=?%s", nsid_s, sep);
                if (get_value(path_name, ra_s, value, vlen)) {
                        if (as_json)
                                sgj_js_nv_s(jsp, jop, ra_s, value);
                        n += sg_scn3pr(b, blen, n, "  %s=%s%s", ra_s, value,
                                       sep);
                } else
                        n += sg_scn3pr(b, blen, n, "  %s=?%s", ra_s, sep);
                if (get_value(path_name, rem_s, value, vlen)) {
                        if (as_json)
                                sgj_js_nv_s(jsp, jop, rem_s, value);
                        sg_scn3pr(b, blen, n, "  %s=%s%s", rem_s, value, sep);
                } else
                        sg_scn3pr(b, blen, n, "  %s=?%s", rem_s, sep);
                sgj_pr_hr(jsp, "%s%s", b, sing ? "" : "\n");
                n = 0;
                if (op->long_opt > 1) {
                        if (get2_value(path_name, qu_s, nrq_s, value, vlen)) {
                                if (as_json)
                                        sgj_js_nv_s(jsp, jop, nrq_s, value);
                                n += sg_scn3pr(b, blen, n, "  %s=%s%s", nrq_s,
                                               value, sep);
                        } else
                                n += sg_scn3pr(b, blen, n, "  %s=?%s", nrq_s,
                                               sep);
                        if (get2_value(path_name, qu_s, rakb_s, value,
                                       vlen)) {
                                if (as_json)
                                        sgj_js_nv_s(jsp, jop, rakb_s, value);
                                n += sg_scn3pr(b, blen, n, "  %s=%s%s",
                                               rakb_s, value, sep);
                        } else
                                n += sg_scn3pr(b, blen, n, "  %s=?%s", rakb_s,
                                               sep);
                        if (get2_value(path_name, qu_s, wc_s, value, vlen)) {
                                if (as_json)
                                        sgj_js_nv_s(jsp, jop, wc_s, value);
                                sg_scn3pr(b, blen, n, "  %s=%s%s", wc_s,
                                          value, sep);
                        } else
                                sg_scn3pr(b, blen, n, "  %s=?%s", wc_s, sep);
                        sgj_pr_hr(jsp, "%s%s", b, sing ? "" : "\n");
                        n = 0;
                        if (get2_value(path_name, qu_s, lbs_sn, value, vlen)) {
                                if (as_json)
                                        sgj_js_nv_s(jsp, jop, lbs_sn, value);
                                n += sg_scn3pr(b, blen, n, "  %s=%s%s",
                                               lbs_sn, value, sep);
                        } else
                                n += sg_scn3pr(b, blen, n, "  %s=?%s", lbs_sn,
                                               sep);
                        if (get2_value(path_name, qu_s, pbs_sn, value,
                                       vlen)) {
                                if (as_json)
                                        sgj_js_nv_s(jsp, jop, pbs_sn, value);
                                sg_scn3pr(b, blen, n, "  %s=%s%s", pbs_sn,
                                          value, sep);
                        } else
                                sg_scn3pr(b, blen, n, "  %s=?%s", pbs_sn,
                                          sep);
                        sgj_pr_hr(jsp, "%s%s", b, sing ? "" : "\n");
                }
                // if (! sing)
                        // printf("\n");
        }
}

#endif          /* (HAVE_NVME && (! IGNORE_NVME)) */

/* Leave this function as plain text only (i.e. no JSON rendering) . */
static void
one_classic_sdev_entry(const char * dir_name, const char * devname,
                       struct lsscsi_opts * op)
{
        int type, scsi_level;
        char buff[LMAX_DEVPATH];
        char wd[LMAX_PATH];
        char dev_node[LMAX_NAME];
        char value[LMAX_NAME];
        struct addr_hctl hctl;
        static const char * ansi_ver_s = "ANSI SCSI revision:";

        snprintf(buff, sizeof(buff), "%s/%s", dir_name, devname);
        if (! parse_colon_list(devname, &hctl))
                invalidate_hctl(&hctl);
        printf("Host: scsi%d Channel: %02d Target: %02d Lun: %02" PRIu64 "\n",
               hctl.h, hctl.c, hctl.t, hctl.l);

        if (get_value(buff, vend_s, value, sizeof(value)))
                printf("  Vendor: %-8s", value);
        else
                printf("  Vendor: ?       ");
        if (get_value(buff, model_s, value, sizeof(value)))
                printf(" Model: %-16s", value);
        else
                printf(" Model: ?               ");
        if (get_value(buff, rev_s, value, sizeof(value)))
                printf(" Rev: %-4s", value);
        else
                printf(" Rev: ?   ");
        printf("\n");
        if (! get_value(buff, "type", value, sizeof(value))) {
                printf("  Type:   %-33s", "?");
        } else if (1 != sscanf(value, "%d", &type)) {
                printf("  Type:   %-33s", "??");
        } else if ((type < 0) || (type > 31)) {
                printf("  Type:   %-33s", "???");
        } else  /* PDT */
                printf("  Type:   %-33s", scsi_device_types[type]);
        if (! get_value(buff, "scsi_level", value, sizeof(value))) {
                printf("%s ?\n", ansi_ver_s);
        } else if (1 != sscanf(value, "%d", &scsi_level)) {
                printf("%s ??\n", ansi_ver_s);
        } else if (scsi_level == 0) {
                printf("%s %s\n", ansi_ver_s, none_s);
        } else
                printf("%s %02x\n", ansi_ver_s,
                       (scsi_level - 1) ? scsi_level - 1 : 1);
        if (op->generic) {
                if (if_directory_ch2generic(buff)) {
                        if (NULL == getcwd(wd, sizeof(wd)))
                                printf("generic_dev error\n");
                        else {
                                if (op->kname)
                                        snprintf(dev_node, sizeof(dev_node),
                                                 "%s/%s", dev_dir_s,
                                                 basename(wd));
                                else if (! get_dev_node(wd, dev_node,
                                                        CHR_DEV))
                                        snprintf(dev_node, sizeof(dev_node),
                                                 "-");
                                printf("%s\n", dev_node);
                        }
                }
                else
                        printf("-\n");
        }
        if (op->long_opt > 0)
                longer_sdev_entry(buff, devname, op, NULL);
        if (op->verbose)
                printf("  dir: %s\n", buff);
}

static void
tag_lun_helper(int * tag_arr, int kk, int num)
{
        int j;

        for (j = 0; j < num; ++j)
                tag_arr[(2 * kk) + j] = ((kk > 0) && (0 == j)) ? 2 : 1;
}

/* Tag lun bytes according to SAM-5 rev 10. Write output to tag_arr assumed
 * to have at least 8 ints. 0 in tag_arr means this position and higher can
 * be ignored; 1 means print as is; 2 means print with separator
 * prefixed. Example: lunp: 01 22 00 33 00 00 00 00 generates tag_arr
 * of 1, 1, 2, 1, 0 ... 0 and might be printed as 0x0122_0033 . */
static void
tag_lun(const uint8_t * lunp, int * tag_arr)
{
        bool next_level;
        int k, a_method, bus_id, len_fld, e_a_method;
        uint8_t not_spec[2] = {0xff, 0xff};

        if (NULL == tag_arr)
                return;
        for (k = 0; k < 8; ++k)
                tag_arr[k] = 0;
        if (NULL == lunp)
                return;
        if (0 == memcmp(lunp, not_spec, sizeof(not_spec))) {
                for (k = 0; k < 2; ++k)
                        tag_arr[k] = 1;
                return;
        }
        for (k = 0; k < 4; ++k, lunp += 2) {
                next_level = false;
                a_method = (lunp[0] >> 6) & 0x3;
                switch (a_method) {
                case 0:         /* peripheral device addressing method */
                        bus_id = lunp[0] & 0x3f;
                        if (bus_id)
                                next_level = true;
                        tag_lun_helper(tag_arr, k, 2);
                        break;
                case 1:         /* flat space addressing method */
                        tag_lun_helper(tag_arr, k, 2);
                        break;
                case 2:         /* logical unit addressing method */
                        tag_lun_helper(tag_arr, k, 2);
                        break;
                case 3:         /* extended logical unit addressing method */
                        len_fld = (lunp[0] & 0x30) >> 4;
                        e_a_method = lunp[0] & 0xf;
                        if ((0 == len_fld) && (1 == e_a_method))
                                tag_lun_helper(tag_arr, k, 2);
                        else if ((1 == len_fld) && (2 == e_a_method))
                                tag_lun_helper(tag_arr, k, 4);
                        else if ((2 == len_fld) && (2 == e_a_method))
                                tag_lun_helper(tag_arr, k, 6);
                        else if ((3 == len_fld) && (0xf == e_a_method))
                                tag_arr[2 * k] = (k > 0) ? 2 : 1;
                        else {
                                if (len_fld < 2)
                                        tag_lun_helper(tag_arr, k, 4);
                                else {
                                        tag_lun_helper(tag_arr, k, 6);
                                        if (3 == len_fld) {
                                                tag_arr[(2 * k) + 6] = 1;
                                                tag_arr[(2 * k) + 7] = 1;
                                        }
                                }
                        }
                        break;
                default:
                        tag_lun_helper(tag_arr, k, 2);
                        break;
                }
                if (! next_level)
                        break;
        }
}

/* Return true for direct access, cd/dvd, rbc and host managed zbc */
static inline bool
is_direct_access_dev(int pdt)
{
        return ((0x0 == pdt) || (0x5 == pdt) || (0xe == pdt) ||
                (0x14 == pdt));
}

/* List one SCSI device (LU) on a line. */
static void
one_sdev_entry(const char * dir_name, const char * devname,
               struct lsscsi_opts * op, sgj_opaque_p jop)
{
        bool get_wwn = false;
        bool as_json;
        int n;
        int dec_pdt = 0;        /* decoded PDT; called 'type' in sysfs */
        int q = 0;
        int devname_len = 13;
        sgj_state * jsp = &op->json_st;
        sgj_opaque_p jo2p = NULL;
        const char * cp = NULL;
        char buff[LMAX_PATH];
        char extra[LMAX_DEVPATH];
        char value[LMAX_NAME];
        char wd[LMAX_PATH];
        char dev_node[LMAX_NAME] = "";
        char b[512];
        char e[256];
        struct addr_hctl hctl;
        static const int blen = sizeof(b);
        static const int elen = sizeof(e);
        static const int vlen = sizeof(value);
        static const int lun_sz = sizeof(hctl.lun_arr);
        static const int dev_node_sz = sizeof(dev_node);
        /* If string used by another function, moved to file scope */
        static const char * hi_s = "host_index";
        static const char * ci_s = "controller_index";
        static const char * ti_s = "target_index";
        static const char * llun_s = "linux_lun";
        static const char * t10_lun_s = "t10_lun_array";
        static const char * hctl_s = "hctl_string";
        static const char * sp32_s = "                                ";

        as_json = jsp->pr_as_json;
        if (op->classic) {
                one_classic_sdev_entry(dir_name, devname, op);
                return;
        }
        snprintf(buff, sizeof(buff), "%s/%s", dir_name, devname);
        if (op->lunhex && parse_colon_list(devname, &hctl)) {
                int sel_mask = 0xf;

                sel_mask |= (1 == op->lunhex) ? 0x10 : 0x20;
                cp = tuple2string(&hctl, sel_mask, elen, e);
                snprintf(value, vlen, "[%s]", cp);
                if (as_json) {
                        sgj_js_nv_s_nex(jsp, jop, lsscsi_loc_s, value,
                                        hctl_s);
                        sgj_js_nv_i(jsp, jop, hi_s, hctl.h);
                        sgj_js_nv_i(jsp, jop, ci_s, hctl.c);
                        sgj_js_nv_i(jsp, jop, ti_s, hctl.t);
                        jo2p = sgj_named_subobject_r(jsp, jop, lun_s);
                        sgj_js_nv_ihex(jsp, jo2p, llun_s, hctl.l);
                        sgj_js_nv_hex_bytes(jsp, jo2p, t10_lun_s,
                                            hctl.lun_arr, lun_sz);
                        if (op->long_opt > 0)
                                sgj_js_nv_s_nex(jsp, jo2p, nm_s,
                                                "Logical Unit Number",
                                                "usually expressed as LUN");
                }
                devname_len = 28;
        } else {
                snprintf(value, vlen, "[%s]", devname);
                if (as_json) {
                        sgj_js_nv_s_nex(jsp, jop, lsscsi_loc_s, value,
                                        hctl_s);
                        if (parse_colon_list(devname, &hctl)) {
                                sgj_js_nv_i(jsp, jop, hi_s, hctl.h);
                                sgj_js_nv_i(jsp, jop, ci_s, hctl.c);
                                sgj_js_nv_i(jsp, jop, ti_s, hctl.t);
                                jo2p = sgj_named_subobject_r(jsp, jop, lun_s);
                                sgj_js_nv_ihex(jsp, jo2p, llun_s, hctl.l);
                                sgj_js_nv_hex_bytes(jsp, jo2p, t10_lun_s,
                                                    hctl.lun_arr, lun_sz);
                                if (op->long_opt > 0)
                                        sgj_js_nv_s(jsp, jo2p, nm_s,
                                                    "Logical Unit Number");
                        }
                }
        }

        if ((int)strlen(value) >= devname_len) /* if long, append a space */
                q += sg_scn3pr(b, blen, q, "%s ", value);
        else /* left justified with field length of devname_len */
                q += sg_scn3pr(b, blen, q, "%-*s", devname_len, value);
        if (op->pdt) {
                if (get_value(buff, "type", value, vlen) &&
                    (1 == sscanf(value, "%d", &dec_pdt)) &&
                    (dec_pdt >= 0) && (dec_pdt < 32))
                        snprintf(e, elen, "0x%x", dec_pdt);
                else
                        snprintf(e, elen, "-1");
                q += sg_scn3pr(b, blen, q, "%-8s", e);
        } else if (op->brief)
                ;
        else if (! get_value(buff, "type", value, vlen)) {
                q += sg_scn3pr(b, blen, q, "type?   ");
        } else if (1 != sscanf(value, "%d", &dec_pdt)) {
                q += sg_scn3pr(b, blen, q, "type??  ");
        } else if ((dec_pdt < 0) || (dec_pdt > 31)) {
                q += sg_scn3pr(b, blen, q, "type??? ");
        } else {
                cp = scsi_short_device_types[dec_pdt];
                q += sg_scn3pr(b, blen, q, "%s ", cp);
                sgj_js_nv_ihexstr(jsp, jop, pdt_sn, dec_pdt, NULL, cp);
        }

        if (op->wwn)
                get_wwn = true;
        if (op->transport_info) {
                if (transport_tport(devname, op, vlen, value))
                        q += sg_scn3pr(b, blen, q, "%-30s  ", value);
                else
                        q += sg_scn3pr(b, blen, q,
                                       "                                ");
        } else if (op->unit) {
                get_lu_name(devname, value, vlen, op->unit > 3);
                n = strlen(value);
                if (n < 1)      /* left justified "none" means no lu name */
                        q += sg_scn3pr(b, blen, q, "%-32s  ", none_s);
                else if (1 == op->unit) {
                        if (n < 33)
                                q += sg_scn3pr(b, blen, q, "%-32s  ", value);
                        else {
                                value[32] = '_';
                                value[33] = ' ';
                                value[34] = '\0';
                                q += sg_scn3pr(b, blen, q, "%-34s", value);
                        }
                } else if (2 == op->unit) {
                        if (n < 33)
                                q += sg_scn3pr(b, blen, q, "%-32s  ", value);
                        else {
                                value[n - 32] = '_';
                                q += sg_scn3pr(b, blen, q, "%-32s  ",
                                               value + n - 32);
                        }
                } else     /* -uuu, output in full, append rest of line */
                        q += sg_scn3pr(b, blen, q, "%-s  ", value);
        } else if (! op->brief) {
                if (as_json)
                        jo2p = sgj_named_subobject_r(jsp, jop,
                                                     "t10_id_strings");
                if (get_value(buff, vend_s, value, vlen)) {
                        q += sg_scn3pr(b, blen, q, "%-8s ", value);
                        if (as_json)
                                sgj_js_nv_s(jsp, jo2p, vend_sn, value);
                } else
                        q += sg_scn3pr(b, blen, q, "vendor?  ");

                if (get_value(buff, model_s, value, vlen)) {
                        q += sg_scn3pr(b, blen, q, "%-16s ", value);
                        if (as_json)
                                sgj_js_nv_s(jsp, jo2p, product_sn, value);
                } else
                        q += sg_scn3pr(b, blen, q, "model?           ");

                if (get_value(buff, rev_s, value, vlen)) {
                        q += sg_scn3pr(b, blen, q, "%-4s  ", value);
                        if (as_json)
                                sgj_js_nv_s(jsp, jo2p, revis_s, value);
                } else
                        q += sg_scn3pr(b, blen, q, "rev?  ");
        }

        if (1 == non_sg_scan(buff, op)) {       /* expect 1 or 0 */
                if (DT_DIR == non_sg.d_type) {
                        sg_scnpr(wd, sizeof(wd), "%s/%s", buff, non_sg.name);
                        if (1 == scan_for_first(wd, op))
                                my_strcopy(extra, aa_first.name,
                                           sizeof(extra));
                        else {
                                q += sg_scn3pr(b, blen, q, "unexpected "
                                               "scan_for_first error");
                                wd[0] = '\0';
                        }
                } else {
                        my_strcopy(wd, buff, sizeof(wd));
                        my_strcopy(extra, non_sg.name, sizeof(extra));
                }
                if (wd[0] && (if_directory_chdir(wd, extra))) {
                        if (NULL == getcwd(wd, sizeof(wd))) {
                                q += sg_scn3pr(b, blen, q, "getcwd error");
                                wd[0] = '\0';
                        }
                }
                if (wd[0]) {
                        enum dev_type d_typ;
                        char wwn_str[DSK_WWN_MXLEN];

                        d_typ = (FT_BLOCK == non_sg.ft) ? BLK_DEV : CHR_DEV;
                        if (get_wwn) {
                                if ((BLK_DEV == d_typ) &&
                                    get_disk_wwn(wd, wwn_str, sizeof(wwn_str),
                                                 op->wwn_twice))
                                        q += sg_scn3pr(b, blen, q, "%-*s  ",
                                                       DSK_WWN_MXLEN - 1,
                                                       wwn_str);
                                else
                                        q += sg_scn3pr(b, blen, q, "%s",
                                                       sp32_s);
                        }
                        cp = NULL;
                        if (op->kname) {
                                cp = "kernel_device_node";
                                snprintf(dev_node, dev_node_sz, "%s/%s",
                                         dev_dir_s, basename(wd));
                        } else {
                                if (get_dev_node(wd, dev_node, d_typ))
                                        cp = "primary_device_node";
                                else
                                        snprintf(dev_node, dev_node_sz,
                                                 "-       ");
                        }
                        q += sg_scn3pr(b, blen, q, "%-9s", dev_node);
                        if (cp && as_json)
                                sgj_js_nv_s(jsp, jop, cp, dev_node);

                        if (op->dev_maj_min) {
                                if (get_value(wd, dv_s, value, vlen)) {
                                        q += sg_scn3pr(b, blen, q, "[%s]",
                                                       value);
                                        if (as_json)
                                                sgj_js_nv_s(jsp, jop,
                                                            "major_minor",
                                                            value);
                                } else
                                        q += sg_scn3pr(b, blen, q, "[dev?]");
                        }

                        if (op->scsi_id) {
                                char *scsi_id;

                                scsi_id = get_disk_scsi_id(dev_node,
                                                           op->scsi_id_twice);
                                q += sg_scn3pr(b, blen, q, "  %s",
                                               scsi_id ? scsi_id : "-");
                                if (scsi_id && as_json)
                                        sgj_js_nv_s(jsp, jop, "scsi_id",
                                                    scsi_id);
                                free(scsi_id);
                        }
                }
        } else {        /* non_sg_scan() didn't return 1, probably 0 */
                if (get_wwn)
                        q += sg_scn3pr(b, blen, q, "%s", sp32_s);
                if (op->scsi_id)
                        q += sg_scn3pr(b, blen, q, "%-9s  -", "-");
                else
                        q += sg_scn3pr(b, blen, q, "%-9s", "-");
        }

        if (op->generic) {
                if (if_directory_ch2generic(buff)) {
                        if (NULL == getcwd(wd, sizeof(wd)))
                                q += sg_scn3pr(b, blen, q,
                                               "  generic_dev error");
                        else {
                                cp = NULL;
                                dev_node[0] = '\0';
                                if (op->kname) {
                                        cp = "sg_kernel_node";
                                        snprintf(dev_node, dev_node_sz,
                                                 "%s/%s", dev_dir_s,
                                                 basename(wd));
                                } else {
                                        if (get_dev_node(wd, dev_node,
                                                         CHR_DEV))
                                                cp = "sg_node";
                                        else
                                                snprintf(dev_node,
                                                         dev_node_sz, "-");
                                }
                                q += sg_scn3pr(b, blen, q, "  %-9s",
                                               dev_node);
                                if (cp && as_json)
                                        sgj_js_nv_s(jsp, jop, cp, dev_node);
                                if (op->dev_maj_min) {
                                        if (get_value(wd, dv_s, value,
                                                      vlen)) {
                                                q += sg_scn3pr(b, blen, q,
                                                               "[%s]", value);
                                                if (as_json)
                                                        sgj_js_nv_s(jsp, jop,
                                                            "sg_major_minor",
                                                                    value);
                                        } else
                                                q += sg_scn3pr(b, blen, q,
                                                               "[dev?]");
                                }
                        }
                } else
                        q += sg_scn3pr(b, blen, q, "  %-9s", "-");
        }
        if (op->protection || op->protmode)
                q += rend_prot_protmode(buff, b + q, blen - q, true, " ",
                                        op, jop);

        if (op->ssize) {
                uint64_t blk512s;
                int64_t num_by = 0;
                char * vp = value;
                char blkdir[LMAX_DEVPATH];

                my_strcopy(blkdir, buff, sizeof(blkdir));
                value[0] = 0;
                if (! (is_direct_access_dev(dec_pdt) &&
                       block_scan(blkdir) &&
                       if_directory_chdir(blkdir, ".") &&
                       get_value(".", "size", vp, vlen))) {
                        /* q += */ sg_scn3pr(b, blen, q, "  %6s", "-");
                        goto fini_line;
                }
                blk512s = atoll(vp);
                num_by = blk512s * 512;
                if (as_json) {
                        sgj_js_nv_s_nex(jsp, jop, "size", vp,
                                        "[unit: 512 bytes]");
                        jo2p = sgj_named_subobject_r(jsp, jop, "size_decomp");
                        sgj_js_nv_ihex_nex(jsp, jo2p, "blocks_512",
                                           blk512s, true,
                                           "[unit: 512 bytes]");
                        sgj_js_nv_ihex(jsp, jo2p, "number_of_bytes", num_by);
                }
                if (op->ssize > 2) {
                        int lbs = 0;
                        char bb[32];
                        static const int bblen = sizeof(bb);

                        if (get2_value(".", qu_s, lbs_sn, bb, bblen))
                                lbs = atoi(bb);
                        if (512 == lbs)
                                q += sg_scn3pr(b, blen, q, "  %12s%s", vp,
                                               (op->ssize > 3) ? ",512" : "");
                        else if (lbs > 512) {
                                snprintf(vp, vlen, "%" PRId64,
                                         (num_by / lbs));
                                if (op->ssize > 3)
                                        q += sg_scn3pr(b, blen, q,
                                                       "  %12s,%d", vp, lbs);
                                else
                                        q += sg_scn3pr(b, blen, q, "  %12s",
                                                       vp);
                        }
                        if (as_json && jo2p) {
                                sgj_js_nv_ihex_nex(jsp, jo2p, lbs_sn, lbs,
                                                   true, "t10 name: Logical "
                                                   "block length in bytes");
                                if (get2_value(".", qu_s, pbs_sn, bb, bblen)) {
                                        lbs = atoi(bb);
                                        sgj_js_nv_ihex(jsp, jo2p, pbs_sn, lbs);
                                }
                                sgj_js_nv_ihex(jsp, jo2p, mbs_s,
                                                num_by / 1000000);
                                sgj_js_nv_ihex(jsp, jo2p, gbs_s,
                                                num_by / 1000000000);
                        } else
                                q += sg_scn3pr(b, blen, q, "  %12s,512", vp);
                } else {
                        enum string_size_units unit_val = (0x1 & op->ssize) ?
                                         STRING_UNITS_10 : STRING_UNITS_2;

                        blk512s <<= 9;
                        if (blk512s > 0 &&
                            size2string(blk512s, unit_val, vp, vlen))
                                q += sg_scn3pr(b, blen, q, "  %6s", vp);
                        else
                                q += sg_scn3pr(b, blen, q, "  %6s", "-");
                }
                if (op->verbose > 6)    /* stop 'unused' compiler noise */
                        pr2serr("%s: actual blen=%d\n", __func__, q);
        }

fini_line:
        sgj_pr_hr(jsp, "%s\n", b);
        if (op->long_opt > 0)
                longer_sdev_entry(buff, devname, op, jop);
        if (op->verbose > 0) {
                q = sg_scn3pr(b, blen, 0, "  dir: %s  [", buff);
                if (if_directory_chdir(buff, "")) {
                        if (NULL == getcwd(wd, sizeof(wd)))
                                sg_scn3pr(b, blen, q, "?");
                        else
                                sg_scn3pr(b, blen, q, "%s", wd);
                }
                sgj_pr_hr(jsp, "%s]\n", b);
        }
}

static int
sdev_dir_scan_select(const struct dirent * s)
{
/* Following no longer needed but leave for early lk 2.6 series */
        if (strstr(s->d_name, "mt"))
                return 0;       /* st auxiliary device names */
        if (strstr(s->d_name, "ot"))
                return 0;       /* osst auxiliary device names */
        if (strstr(s->d_name, "gen"))
                return 0;
/* Above no longer needed but leave for early lk 2.6 series */
        if (!strncmp(s->d_name, "host", 4)) /* SCSI host */
                return 0;
        if (!strncmp(s->d_name, "target", 6)) /* SCSI target */
                return 0;
        if (strchr(s->d_name, ':')) {
                if (filter_active) {
                        struct addr_hctl s_hctl;

                        if (! parse_colon_list(s->d_name, &s_hctl)) {
                                pr2serr("%s: parse failed\n", __func__);
                                return 0;
                        }
                        if (((-1 == filter.h) || (s_hctl.h == filter.h)) &&
                            ((-1 == filter.c) || (s_hctl.c == filter.c)) &&
                            ((-1 == filter.t) || (s_hctl.t == filter.t)) &&
                            ((UINT64_LAST == filter.l) ||
                             (s_hctl.l == filter.l)))
                                return 1;
                        else
                                return 0;
                } else
                        return 1;
        }
        /* Still need to filter out "." and ".." */
        return 0;
}

#if (HAVE_NVME && (! IGNORE_NVME))

/* List one NVMe namespace (NS) on a line. */
static void
one_ndev_entry(const char * nvme_ctl_abs, const char * nvme_ns_rel,
               struct lsscsi_opts * op, sgj_opaque_p jop)
{
        bool as_json;
        int m;
        int q = 0;
        int cdev_minor = 0;
        int cntlid = 0;
        int vb = op->verbose;
        int devname_len = 13;
        int sel_mask = 0xf;
        uint32_t nsid = 0;
        char * cp;
        const char * ccp;
        sgj_state * jsp = &op->json_st;
        sgj_opaque_p jo2p = NULL;
        char buff[LMAX_DEVPATH];
        char value[LMAX_NAME];
        char dev_node[LMAX_NAME + 16] = "";
        char wd[LMAX_PATH];
        char devname[64];
        char ctl_model[48];
        char b[256];
        char bb[80];
        char d[80];
        char e[80];
        const int bufflen = sizeof(buff);
        const int vlen = sizeof(value);
        struct addr_hctl hctl;
        static const int model_len = 30;        /* was 41 */
        static const int blen = sizeof(b);
        static const int bblen = sizeof(bb);
        static const int devnlen = sizeof(dev_node);
        static const int dlen = sizeof(d);
        static const int elen = sizeof(e);

        as_json = jsp->pr_as_json;
        b[0] = '\0';
        sg_scn3pr(buff, bufflen, 0, "%s/%s", nvme_ctl_abs, nvme_ns_rel);
        if ((0 == strncmp(nvme_ns_rel, "nvme", 4)) &&
            (1 == sscanf(nvme_ns_rel + 4, "%d", &cdev_minor)))
                ;
        else if (vb)
                pr2serr("%s: unable to find %s in %s\n", __func__,
                        "cdev_minor", nvme_ns_rel);

        if (get_value(nvme_ctl_abs, cntlid_s, value, vlen)) {
                if (1 != sscanf(value, "%d", &cntlid)) {
                        if (vb)
                                pr2serr("%s: trying to decode: %s as %s\n",
                                        __func__, value, cntlid_s);
                }
                if (filter_active && (-1 != filter.t) && (cntlid != filter.t))
                        return;         /* doesn't meet filter condition */
        } else if (vb)
                pr2serr("%s: unable to find %s under %s\n", __func__,
                        cntlid_s, nvme_ctl_abs);

#ifdef __cplusplus
        cp = strrchr((char *)nvme_ns_rel, 'n');
#else
        cp = strrchr(nvme_ns_rel, 'n');
#endif
        if ((NULL == cp) || ('v' == *(cp + 1)) ||
            (1 != sscanf(cp + 1, "%u", &nsid))) {
                if (vb)
                        pr2serr("%s: unable to find nsid in %s\n", __func__,
                                nvme_ns_rel);
        }
        mk_nvme_tuple(&hctl, cdev_minor, cntlid, nsid);

        if (op->lunhex) {
                sel_mask |= (1 == op->lunhex) ? 0x10 : 0x20;
                devname_len = 28;
        }
        snprintf(value, vlen, "[%s]",
                 tuple2string(&hctl, sel_mask, sizeof(devname), devname));
        if (as_json) {
                sgj_js_nv_s(jsp, jop, lsscsi_loc_s, value);
                if (cntlid > 0)
                        sgj_js_nv_i(jsp, jop, cntlid_s, cntlid);
                if (get_value(buff, nsid_s, b, blen))
                        sgj_js_nv_s(jsp, jop, nsid_s, b);
                ccp = name_eq2value(buff, "uevent", "DEVTYPE", blen, b);
                if (ccp)
                        sgj_js_nv_s(jsp, jop, "devtype", ccp);
                if (get_value(nvme_ctl_abs, model_s, b, blen)) {
                        trim_lead_trail(b, true, true);
                        sgj_js_nv_s(jsp, jop, model_s, b);
                }
                if (get_value(nvme_ctl_abs, ser_s, b, blen)) {
                        trim_lead_trail(b, true, true);
                        sgj_js_nv_s(jsp, jop, ser_s, b);
                }
                if (get_value(nvme_ctl_abs, fr_s, b, blen)) {
                        trim_lead_trail(b, true, true);
                        sgj_js_nv_s(jsp, jop, fr_s, b);
                }
        }

        if ((int)strlen(value) >= devname_len) /* if long, append a space */
                q += sg_scn3pr(b, blen, q, "%s ", value);
        else /* left justified with field length of devname_len */
                q += sg_scn3pr(b, blen, q, "%-*s", devname_len, value);

        if (op->pdt)
                q += sg_scn3pr(b, blen, q, "%-8s", "0x0");
        else if (op->brief)
                ;
        else if (vb) /* NVMe namespace can only be NVM device */
                q += sg_scn3pr(b, blen, q, "dsk/nvm ");
        else
                q += sg_scn3pr(b, blen, q, "disk    ");

        if (op->transport_info) {
                value[0] = '\0';
                if (get2_value(buff, dvc_s, trans_s, value, vlen)) {
                        const char * bp = buff;
                        static const char * dev2_s = "device/device";

                        if (0 == strcmp(pcie_s, value)) {

                                if (get2_value(bp, dev2_s, svp_s, d, dlen) &&
                                    get2_value(bp, dev2_s, sdp_s, e, elen)) {
                                        snprintf(value , vlen, "%s %s:%s",
                                                 pcie_s, d, e);
                                        q += sg_scn3pr(b, blen, q, "%-*s  ",
                                                       model_len, value);
                                } else
                                        q += sg_scn3pr(b, blen, q, "%-*s  ",
                                                       model_len,
                                                       "transport?");
                        } else
                                q += sg_scn3pr(b, blen, q, "%-*s  ",
                                               model_len, value);
                } else
                        q += sg_scn3pr(b, blen, q, "%-*s  ", model_len,
                                       "transport?");
                if (as_json && value[0])
                        sgj_js_nv_s(jsp, jop, trans_s, value);
        } else if (op->unit) {
                if (get_value(buff, wwid_s, value, vlen)) {
                        if ((op->unit < 4) &&
                            (0 == strncmp("eui.", value, 4))) {
                                q += sg_scn3pr(b, blen, q, "%-*s  ",
                                               model_len, value + 4);
                                if (as_json)
                                        sgj_js_nv_s(jsp, jop, wwid_s,
                                                    value + 4);
                        } else
                                q += sg_scn3pr(b, blen, q, "%-*s  ",
                                               model_len, value);
                } else
                        q += sg_scn3pr(b, blen, q, "%-*s?  ", model_len,
                                       wwid_s);
        } else if (! op->brief) {
                int n;

                if (! get_value(nvme_ctl_abs, model_s, ctl_model,
                                sizeof(ctl_model)))
                        snprintf(ctl_model, sizeof(ctl_model), "-    ");
                n = trim_lead_trail(ctl_model, true, true);
                snprintf(d, dlen, "__%u", nsid);
                m = strlen(d);
                if (n > (model_len - m))
                        memcpy(ctl_model + model_len - m, d, m + 1);
                else
                        strcat(ctl_model, d);
                q += sg_scn3pr(b, blen, q, "%-*s  ", model_len, ctl_model);
        }

        if (op->wwn) {
                if (get_value(buff, wwid_s, value, vlen)) {
                        q += sg_scn3pr(b, blen, q, "%-*s  ", model_len,
                                       value);
                        if (as_json)
                                sgj_js_nv_s(jsp, jop, wwid_s, value);
                } else
                        q += sg_scn3pr(b, blen, q, "%-*s?  ", model_len,
                                       wwid_s);
        }

        if (op->kname) {
                snprintf(dev_node, devnlen, "%s/%s", dev_dir_s, nvme_ns_rel);
                if (as_json)
                        sgj_js_nv_s(jsp, jop, ker_node_s, dev_node);
        } else if (get_dev_node(buff, dev_node, BLK_DEV)) {
                if (as_json)
                        sgj_js_nv_s(jsp, jop, dev_node_s, dev_node);

        } else
                snprintf(dev_node, devnlen, "-       ");

        q += sg_scn3pr(b, blen, q, "%-9s", dev_node);
        if (op->dev_maj_min) {
                if (get_value(buff, dv_s, value, vlen)) {
                        q += sg_scn3pr(b, blen, q, " [%s]", value);
                        if (as_json)
                                sgj_js_nv_s(jsp, jop, dv_s, value);
                } else
                        q += sg_scn3pr(b, blen, q, " [dev?]");
        }
        if (op->generic && (1 == ng_scan(nvme_ctl_abs))) {
                /* found a <nvme_ctl_abs>/ng* 'nvme-generic' device */
                const char * ngp = aa_ng.name;

                sg_scnpr(dev_node, devnlen, "%s/%s", nvme_ctl_abs, ngp);
                // if (get2_value(nvme_ctl_abs, ngp, dv_s, e, elen)) {
                if (op->kname) {
                        snprintf(value, vlen, "%s/%.32s", dev_dir_s, ngp);
                        if (as_json)
                                sgj_js_nv_s(jsp, jop, "ng_kernel_node",
                                            value);
                } else if (get_dev_node(dev_node, value, CHR_DEV)) {
                        if (as_json)
                                sgj_js_nv_s(jsp, jop, "ng_device_node",
                                            value);
                } else
                        snprintf(value, vlen, "%s", "-");
                q += sg_scn3pr(b, blen, q, "  %-9s", value);
        } else if (op->generic)
                q += sg_scn3pr(b, blen, q, "  %-9s", "-");

        if (op->ssize) {
                uint64_t blk512s;
                int64_t num_by = 0;

                if (! get_value(buff, "size", value, vlen)) {
                        sg_scn3pr(b, blen, q, "  %6s", "-");
                        goto fini_line;
                }
                blk512s = atoll(value);
                num_by = blk512s * 512;
                if (as_json) {
                        sgj_js_nv_s_nex(jsp, jop, "size", value,
                                        "[unit: 512 bytes]");
                        jo2p = sgj_named_subobject_r(jsp, jop, "size_decomp");
                        sgj_js_nv_ihex_nex(jsp, jo2p, "blocks_512",
                                           blk512s, true,
                                           "[unit: 512 bytes]");
                        sgj_js_nv_ihex(jsp, jo2p, "number_of_bytes", num_by);
                }
                if (op->ssize > 2) {
                        int lbs = 0;
                        int pbs = 0;
                        char * vp = value;

                        if (get2_value(buff, qu_s, lbs_sn, bb, bblen)) {
                                lbs = atoi(bb);
                                if (as_json)
                                        sgj_js_nv_ihex(jsp, jo2p, lbs_sn, lbs);
                        }
                        if (as_json && get2_value(buff, qu_s, pbs_sn, bb,
                                                  bblen)) {
                                pbs = atoi(bb);
                                sgj_js_nv_ihex(jsp, jo2p, pbs_sn, pbs);
                        }
                        if (512 == lbs)
                                sg_scn3pr(b, blen, q, "  %12s%s", vp,
                                          (op->ssize > 3) ? ",512" : "");
                        else if (lbs > 512) {
                                sg_scn3pr(vp, vlen, 0, "%" PRId64,
                                          (num_by / lbs));
                                if (op->ssize > 3)
                                        sg_scn3pr(b, blen, q, "  %12s,%d", vp,
                                                  lbs);
                                else
                                        sg_scn3pr(b, blen, q, "  %12s", vp);
                        }
                        if (as_json) {
                                sgj_js_nv_ihex(jsp, jo2p, mbs_s,
                                                num_by / 1000000);
                                sgj_js_nv_ihex(jsp, jo2p, gbs_s,
                                                num_by / 1000000000);
                        }
                } else {
                        enum string_size_units unit_val =
                                        (0x1 & op->ssize) ?  STRING_UNITS_10 :
                                                             STRING_UNITS_2;

                        blk512s <<= 9;
                        if (blk512s > 0 &&
                            size2string(blk512s, unit_val, value, vlen))
                                sg_scn3pr(b, blen, q, "  %6s", value);
                        else
                                sg_scn3pr(b, blen, q, "  %6s", "-");
                }
        }

fini_line:
        sgj_pr_hr(jsp, "%s\n", b);
        if (op->long_opt > 0)
                longer_nd_entry(buff, devname, op, jop);
        if (vb > 0) {
                q = 0;
                q += sg_scn3pr(b, blen, q, "  dir: %s  [", buff);
                if (if_directory_chdir(buff, "")) {
                        if (NULL == getcwd(wd, sizeof(wd)))
                                sg_scn3pr(b, blen, q, "?");
                        else
                                sg_scn3pr(b, blen, q, "%s", wd);
                }
                sgj_pr_hr(jsp, "%s]\n", b);
        }
}

static int
ndev_dir_scan_select(const struct dirent * s)
{
        int cdev_minor; /* /dev/nvme<n> char device minor */

        if ((0 == strncmp(s->d_name, "nvme", 4)) &&
            (1 == sscanf(s->d_name + 4, "%d", &cdev_minor))) {
                if (filter_active) {
                        if (((-1 == filter.h) ||
                             (NVME_HOST_NUM == filter.h)) &&
                            ((-1 == filter.c) || (cdev_minor == filter.c)))
                                return 1;
                        else
                                return 0;
                } else
                        return 1;
        }
        return 0;
}

static int
ndev_dir_scan_select2(const struct dirent * s)
{
        int cdev_minor;
        uint32_t nsid;
        char * cp;

        /* What to do about NVMe controller CNTLID field? */
        if (strncmp(s->d_name, "nvme", 4))
                return 0;
#ifdef __cplusplus
        cp = strchr((char *)s->d_name + 4, 'n');
#else
        cp = strchr(s->d_name + 4, 'n');
#endif
        if (NULL == cp)
                return 0;
        if ((1 == sscanf(s->d_name + 4, "%d", &cdev_minor)) &&
            (1 == sscanf(cp + 1, "%u", &nsid))) {
                if (filter_active) {    /* filter cntlid (.t) in caller */
                        if (((-1 == filter.h) ||
                             (NVME_HOST_NUM == filter.h)) &&
                            ((-1 == filter.c) || (cdev_minor == filter.c)) &&
                      /*    ((-1 == filter.t) || (s_hctl.t == filter.t)) && */
                            ((UINT64_LAST == filter.l) || (nsid == filter.l)))
                                return 1;
                        else
                                return 0;
                } else
                        return 1;
        }
        return 0;
}

static void
one_nhost_entry(const char * dir_name, const char * nvme_ctl_rel,
                struct lsscsi_opts * op, sgj_opaque_p jop)
{
        bool as_json;
        int n = 0;
        int vb = op->verbose;
        uint32_t cdev_minor;
        sgj_state * jsp = &op->json_st;
        char buff[LMAX_DEVPATH];
        char a[LMAX_DEVPATH];
        char value[LMAX_DEVPATH];
        char wd[LMAX_PATH];
        char b[80];
        char bb[80];
        static const int vlen = sizeof(value);
        static const int alen = sizeof(a);
        static const int blen = sizeof(b);
        static const int bblen = sizeof(bb);
        static const char * clw_s = "current_link_width";
        static const char * cls_s = "current_link_speed";
        static const char * ssnq_s = "subsysnqn";

        as_json = jsp->pr_as_json;
        if (1 == sscanf(nvme_ctl_rel, "nvme%u", &cdev_minor)) {
                n += sg_scn3pr(a, alen, n, "[N:%u]", cdev_minor);
                if (as_json)
                        sgj_js_nv_s(jsp, jop, lsscsi_loc_s, a);
                n += sg_scn3pr(a, alen, n, "  ");
        } else
                n += sg_scn3pr(a, alen, n, "[N:?]  ");
        snprintf(buff, sizeof(buff), "%.256s%.32s", dir_name, nvme_ctl_rel);
        if (as_json) {
                if (get_value(buff, cntlid_s, value, vlen))
                        sgj_js_nv_s(jsp, jop, cntlid_s, value);
                if (get_value(buff, model_s, value, vlen)) {
                        trim_lead_trail(value, true, true);
                        sgj_js_nv_s(jsp, jop, model_s, value);
                }
                if (get_value(buff, ser_s, value, vlen)) {
                        trim_lead_trail(value, true, true);
                        sgj_js_nv_s(jsp, jop, ser_s, value);
                }
                if (get_value(buff, fr_s, value, vlen)) {
                        trim_lead_trail(value, true, true);
                        sgj_js_nv_s(jsp, jop, fr_s, value);
                }
                if ((! op->brief) && get_value(buff, addr_s, value, vlen))
                        sgj_js_nv_s(jsp, jop, addr_s, value);
        }
        if (op->kname) {
                snprintf(value, vlen, "%s/%s", dev_dir_s, nvme_ctl_rel);
                if (as_json)
                        sgj_js_nv_s(jsp, jop, ker_node_s, value);
        } else if (get_dev_node(buff, value, CHR_DEV)) {
                if (as_json)
                        sgj_js_nv_s(jsp, jop, dev_node_s, value);
        } else
                snprintf(value, vlen, "-       ");
        n += sg_scn3pr(a, alen, n, "%-9s", value);
        if (op->dev_maj_min) {
                const char * bp;

                bp = name_eq2value(buff, "uevent", "MAJOR", sizeof(b), b);
                if (strlen(bp) > 1) {
                        const char * b2p = name_eq2value(buff, "uevent",
                                                         "MINOR", bblen, bb);

                        sg_scn3pr(value, vlen, 0, "%s:%s", bp, b2p);
                        if (as_json)
                                sgj_js_nv_s(jsp, jop, dv_s, value);
                        n += sg_scn3pr(a, alen, n, " [%s]", value);
                } else
                        n += sg_scn3pr(a, alen, n, " [dev?]");
        }
        if (op->transport_info) {
                n += sg_scn3pr(a, alen, n, "    ");
                if (get_value(buff, trans_s, value, vlen)) {
                        if (0 == strcmp(pcie_s, value)) {
                                if (get2_value(buff, dvc_s, svp_s, b, blen) &&
                                    get2_value(buff, dvc_s, sdp_s, bb, bblen))
                                        sg_scn3pr(a, alen, n, "%s %s:%s",
                                                  pcie_s, b, bb);
                                else
                                        sg_scn3pr(a, alen, n, "%s ?:?",
                                                  pcie_s);
                        } else
                                sg_scn3pr(a, alen, n, "%s%s",
                                          (vb ? "transport=" : ""), value);
                } else if (vb)
                        sg_scn3pr(a, alen, n, "%s=?", trans_s);
                sgj_pr_hr(jsp, "%s\n", a);
                n = 0;
        } else if (op->wwn) {
                if (get_value(buff, ssnq_s, value, vlen)) {
                        if (as_json)
                                sgj_js_nv_s(jsp, jop, ssnq_s, value);
                        sgj_pr_hr(jsp, "%s   %s%s\n", a, (vb ? ssnq_s : ""),
                                  value);
                } else if (vb)
                        sgj_pr_hr(jsp, "%s %s=?\n", a, ssnq_s);
                n = 0;
        } else if (op->unit) {
                if (get2_value(buff, dvc_s, svp_s, value, vlen)) {
                        sg_scn3pr(a, alen, n, "   %s%s:",
                                  (vb ? "vin=" : ""), value);
                        if (as_json)
                                sgj_js_nv_s(jsp, jop, svp_s, value);
                        if (get2_value(buff, dvc_s, sdp_s, value, vlen)) {
                                sgj_pr_hr(jsp, "%s%s\n", a, value);
                                if (as_json)
                                        sgj_js_nv_s(jsp, jop, sdp_s, value);
                        } else
                                sgj_pr_hr(jsp, "%s??\n", a);
                } else if (vb)
                        sgj_pr_hr(jsp, "%s%s=?\n", a, svp_s);
                n = 0;
        } else if (op->long_opt > 0) {
                bool sing = (op->long_opt > 2);
                const char * sep = sing ? "\n" : "";

                if (! sing) { /* leave host single line the same, like SCSI */
                        sgj_pr_hr(jsp, "%s\n", a);
                        n = 0;
                }
                if (get_value(buff, cntlid_s, value, vlen)) {
                        n += sg_scn3pr(a, alen, n, "%s  %s=%s%s", sep,
                                       cntlid_s, value, sep);
                } else if (vb)
                        n += sg_scn3pr(a, alen, n, "%s  %s=?%s", sep,
                                       cntlid_s, sep);
                if (get_value(buff, stat_s, value, vlen)) {
                        if (as_json)
                                sgj_js_nv_s(jsp, jop, stat_s, value);
                        n += sg_scn3pr(a, alen, n, "  %s=%s%s", stat_s, value,
                                       sep);
                } else if (vb)
                        n += sg_scn3pr(a, alen, n, "  %s=?%s", stat_s, sep);
                if (get2_value(buff, dvc_s, clw_s, value, vlen)) {
                        if (as_json)
                                sgj_js_nv_s(jsp, jop, clw_s, value);
                        n += sg_scn3pr(a, alen, n, "  %s=%s%s", clw_s, value,
                                       sep);
                } else if (vb)
                        n += sg_scn3pr(a, alen, n, "  %s=?%s", clw_s, sep);
                if (get_value(buff, fr_s, value, vlen))
                        n += sg_scn3pr(a, alen, n, "  %s=%s%s", fr_s, value,
                                       sep);
                else if (vb)
                        n += sg_scn3pr(a, alen, n, "  %s=?%s", fr_s, sep);
                if (! sing) {
                        sgj_pr_hr(jsp, "%s\n", a);
                        n = 0;
                }
                if (op->long_opt > 1) {
                        if (get2_value(buff, dvc_s, cls_s, value, vlen)) {
                                if (as_json)
                                        sgj_js_nv_s(jsp, jop, cls_s, value);
                                n += sg_scn3pr(a, alen, n, "  %s=%s%s", cls_s,
                                               value, sep);
                        } else if (vb)
                                n += sg_scn3pr(a, alen, n, "  %s=?%s", cls_s,
                                               sep);
                        if (get_value(buff, model_s, value, vlen)) {
                                trim_lead_trail(value, true, true);
                                n += sg_scn3pr(a, alen, n, "  %s=%s%s",
                                               model_s, value, sep);
                        } else if (vb)
                                n += sg_scn3pr(a, alen, n, "  %s=?%s",
                                               model_s, sep);
                        if (get_value(buff, ser_s, value, vlen)) {
                                trim_lead_trail(value, true, true);
                                n += sg_scn3pr(a, alen, n, "  %s=%s%s", ser_s,
                                               value, sep);
                        } else if (vb)
                                n += sg_scn3pr(a, alen, n, "  %s=?%s", ser_s,
                                               sep);
                        if (! sing) {
                                sgj_pr_hr(jsp, "%s\n", a);
                                n = 0;
                        }
                }
        } else if (! op->brief) {
                if (get_value(buff, model_s, value, vlen) &&
                    strncmp(value, nulln1_s, 6) &&
                    strncmp(value, nulln2_s, 6)) {
                        trim_lead_trail(value, true, true);
                        trunc_pad2n(value, 32, true);
                } else
                        strcpy(value, nulln1_s);
                n += sg_scn3pr(a, alen, n, "  %-32s ", value);

                if (get_value(buff, ser_s, value, vlen) &&
                    strncmp(value, nulln1_s, 6) &&
                    strncmp(value, nulln2_s, 6)) {
                        trim_lead_trail(value, true, true);
                        trunc_pad2n(value, 18, true);
                } else
                        strcpy(value, nulln1_s);
                n += sg_scn3pr(a, alen, n, " %-18s ", value);

                if (get_value(buff, fr_s, value, vlen) &&
                    strncmp(value, nulln1_s, 6) &&
                    strncmp(value, nulln2_s, 6)) {
                        trim_lead_trail(value, true, true);
                        trunc_pad2n(value, 8, false);
                } else
                        strcpy(value, nulln1_s);
                n += sg_scn3pr(a, alen, n, " %-8s", value);
        } else {
                sgj_pr_hr(jsp, "%s\n", a);
                n = 0;
        }
        if (n > 0)
                sgj_pr_hr(jsp, "%s\n", a);
        if (vb > 0) {
                n = sg_scn3pr(a, alen, 0, "  dir: %s\n  device dir: ", buff);
                if (if_directory_chdir(buff, dvc_s)) {
                        if (NULL == getcwd(wd, sizeof(wd)))
                                sg_scn3pr(a, alen, n, "?");
                        else
                                sg_scn3pr(a, alen, n, "%s", wd);
                }
                sgj_pr_hr(jsp, "%s\n", a);
        }
}

#endif          /* (HAVE_NVME && (! IGNORE_NVME)) */

/* This is a compare function for numeric sort based on hctl tuple.
 * Returns -1 if (a->d_name < b->d_name) ; 0 if they are equal
 * and 1 otherwise. */
static int
sdev_scandir_sort(const struct dirent ** a, const struct dirent ** b)
{
        const char * lnam = (*a)->d_name;
        const char * rnam = (*b)->d_name;
        struct addr_hctl left_hctl;
        struct addr_hctl right_hctl;

        if (! parse_colon_list(lnam, &left_hctl)) {
                pr2serr("%s: left parse failed: %.20s\n", __func__,
                        (lnam ? lnam : "<null>"));
                return -1;
        }
        if (! parse_colon_list(rnam, &right_hctl)) {
                pr2serr("%s: right parse failed: %.20s\n", __func__,
                        (rnam ? rnam : "<null>"));
                return 1;
        }
        return cmp_hctl(&left_hctl, &right_hctl);
}

#if (HAVE_NVME && (! IGNORE_NVME))

/* This is a compare function for numeric sort based on hctl tuple. Similar
 * to sdev_scandir_sort() but converts entries like "nvme2" into a hctl tuple.
 * Returns -1 if (a->d_name < b->d_name) ; 0 if they are equal
 * and 1 otherwise. */
static int
nhost_scandir_sort(const struct dirent ** a, const struct dirent ** b)
{
        const char * lnam = (*a)->d_name;
        const char * rnam = (*b)->d_name;
        struct addr_hctl left_hctl;
        struct addr_hctl right_hctl;

        if (strchr(lnam, ':')) {
                if (! parse_colon_list(lnam, &left_hctl)) {
                        pr2serr("%s: left parse failed: %.20s\n", __func__,
                                (lnam ? lnam : "<null>"));
                        return -1;
                }
        } else {
                if (1 == sscanf(lnam, "nvme%d", &left_hctl.c)) {
                        left_hctl.h = NVME_HOST_NUM;
                        left_hctl.t = 0;
                        left_hctl.l = 0;
                } else {
                        pr2serr("%s: left sscanf failed: %.20s\n", __func__,
                                (lnam ? lnam : "<null>"));
                        return -1;
                }
        }
        if (strchr(rnam, ':')) {
                if (! parse_colon_list(rnam, &right_hctl)) {
                        pr2serr("%s: right parse failed: %.20s\n", __func__,
                                (rnam ? rnam : "<null>"));
                        return 1;
                }
        } else {
                if (1 == sscanf(rnam, "nvme%d", &right_hctl.c)) {
                        right_hctl.h = NVME_HOST_NUM;
                        right_hctl.t = 0;
                        right_hctl.l = 0;
                } else {
                        pr2serr("%s: right sscanf failed: %.20s\n", __func__,
                                (rnam ? rnam : "<null>"));
                        return -1;
                }
        }
        return cmp_hctl(&left_hctl, &right_hctl);
}

#endif          /* (HAVE_NVME && (! IGNORE_NVME)) */

/* List SCSI devices (LUs). */
static void
list_sdevices(struct lsscsi_opts * op, sgj_opaque_p jop)
{
        int num, k, n, blen, nlen;
        struct dirent ** namelist;
        sgj_state * jsp = &op->json_st;
        sgj_opaque_p jap = NULL;
        sgj_opaque_p jo2p = NULL;
        char buff[LMAX_DEVPATH];
        char name[LMAX_NAME];

        blen = sizeof(buff);
        nlen = sizeof(name);
        snprintf(buff, blen, "%s%s", sysfsroot, bus_scsi_dev_s);

        num = scandir(buff, &namelist, sdev_dir_scan_select,
                      sdev_scandir_sort);
        if (num < 0) {  /* scsi mid level may not be loaded */
                if (op->verbose > 1) {
                        n = 0;
                        n += sg_scn3pr(name, nlen, n, "%s: scandir: ",
                                       __func__);
                        sg_scn3pr(name, nlen, n, "%s", buff);
                        perror(name);
                        sgj_pr_hr(jsp, "SCSI mid level %s\n", mmnbl_s);
                }
                if (op->classic)
                        sgj_pr_hr(jsp, "Attached devices: %s\n", none_s);
                return;
        }
        if (op->classic)
                sgj_pr_hr(jsp, "Attached devices: %s\n", (num ? "" : none_s));

        if (jsp->pr_as_json) {
                sgj_js_nv_i(jsp, jsp->basep,
                            "number_of_attached_scsi_devices", num);
                jap = sgj_named_subarray_r(jsp, jop,
                                           "attached_scsi_device_list");
        }

        for (k = 0; k < num; ++k) {
                my_strcopy(name, namelist[k]->d_name, nlen);
                transport_id = TRANSPORT_UNKNOWN;
                jo2p = sgj_new_unattached_object_r(jsp);
                one_sdev_entry(buff, name, op, jo2p);
                sgj_js_nv_o(jsp, jap, NULL /* implies an array add */, jo2p);
                free(namelist[k]);
        }
        free(namelist);
        if (op->wwn)
                free_disk_wwn_node_list();
}

#if (HAVE_NVME && (! IGNORE_NVME))

/* List NVME devices (namespaces). */
static void
list_ndevices(struct lsscsi_opts * op, sgj_opaque_p jop)
{
        int num, num2, k, j, n, blen, b2len, elen;
        struct dirent ** name_list;
        struct dirent ** namelist2;
        sgj_state * jsp = &op->json_st;
        sgj_opaque_p jap = NULL;
        sgj_opaque_p jo2p = NULL;
        char buff[LMAX_DEVPATH];
        char buff2[LMAX_DEVPATH];
        char ebuf[120];

        blen = sizeof(buff);
        b2len = sizeof(buff2);
        elen = sizeof(ebuf);
        n = sg_scn3pr(buff, blen, 0, "%s", sysfsroot);
        sg_scn3pr(buff, blen, n, "%s", class_nvme);

        num = scandir(buff, &name_list, ndev_dir_scan_select,
                      nhost_scandir_sort);
        if (num < 0) {  /* NVMe module may not be loaded */
                if (op->verbose > 1) {
                        n = sg_scn3pr(ebuf, elen, 0, "%s: scandir: ",
                                      __func__);
                        sg_scn3pr(ebuf, elen, n, "%s", buff);
                        perror(ebuf);
                        sgj_pr_hr(jsp, "NVMe %s\n", mmnbl_s);
                }
                return;
        }
        if (jsp->pr_as_json) {
                sgj_js_nv_i(jsp, jsp->basep,
                            "number_of_attached_nvme_devices", num);
                jap = sgj_named_subarray_r(jsp, jop,
                                           "attached_nvme_device_list");
        }

        for (k = 0; k < num; ++k) {
                n = sg_scn3pr(buff2, b2len, 0, "%s", buff);
                sg_scn3pr(buff2, b2len, n, "%s", name_list[k]->d_name);
                free(name_list[k]);
                num2 = scandir(buff2, &namelist2, ndev_dir_scan_select2,
                               sdev_scandir_sort);
                if (num2 < 0) {
                        if (op->verbose > 0) {
                                n = sg_scn3pr(ebuf, elen, 0,
                                              "%s: scandir(2): ", __func__);
                                sg_scn3pr(ebuf, elen, n, "%s", buff);
                                perror(ebuf);
                        }
                        /* already freed name_list[k] so move to next */
                        ++k;
                        break;
                }
                for (j = 0; j < num2; ++j) {
                        transport_id = TRANSPORT_UNKNOWN;
                        jo2p = sgj_new_unattached_object_r(jsp);
                        one_ndev_entry(buff2, namelist2[j]->d_name, op, jo2p);
                        sgj_js_nv_o(jsp, jap, NULL /* implies an array add */,
                                    jo2p);
                        free(namelist2[j]);
                }
                free(namelist2);
        }
        for ( ; k < num; ++k) /* clean out rest of name_list[] */
                free(name_list[k]);

        free(name_list);
        if (op->wwn)
                free_disk_wwn_node_list();
}

#endif          /* (HAVE_NVME && (! IGNORE_NVME)) */

/* List SCSI host (initiator) attributes when --long given (one or more
 * times). */
static void
longer_sh_entry(const char * path_name, struct lsscsi_opts * op,
                sgj_opaque_p jop)
{
        int n;
        sgj_state * jsp = &op->json_st;
        char value[LMAX_NAME];
        char b[168];
        static const int vlen = sizeof(value);
        static const int blen = sizeof(b);
        static const char * am_s = "active_mode";
        static const char * cq_s = "can_queue";
        static const char * cpl_s = "cmd_per_lun";
        static const char * hb_s = "host_busy";
        static const char * nhq_s = "nr_hw_queues";
        static const char * sgt_s = "sg_tablesize";
        static const char * state_s = "state";
        static const char * ubm_s = "use_blk_mq";

        if (op->transport_info) {
                transport_init_longer(path_name, op, jop);
                return;
        }
        if (op->long_opt >= 3) {
                if (get_value(path_name, am_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, am_s, SEP_EQ_NO_SP, value);
                if (get_value(path_name, cq_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, cq_s, SEP_EQ_NO_SP, value);
                else if (op->verbose)
                        sgj_pr_hr(jsp, "  %s=?\n", cq_s);
                if (get_value(path_name, cpl_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, cpl_s, SEP_EQ_NO_SP, value);
                else if (op->verbose)
                        sgj_pr_hr(jsp, "  %s=?\n", cpl_s);
                if (get_value(path_name, hb_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, hb_s, SEP_EQ_NO_SP, value);
                else if (op->verbose)
                        sgj_pr_hr(jsp, "  %s=?\n", hb_s);
                if (get_value(path_name, nhq_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, nhq_s, SEP_EQ_NO_SP, value);
                else if (op->verbose)
                        sgj_pr_hr(jsp, "  %s=?\n", nhq_s);
                if (get_value(path_name, sgt_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, sgt_s, SEP_EQ_NO_SP, value);
                else if (op->verbose)
                        sgj_pr_hr(jsp, "  %s=?\n", sgt_s);
                if (get_value(path_name, state_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, state_s, SEP_EQ_NO_SP, value);
                else if (op->verbose)
                        sgj_pr_hr(jsp, "  %s=?\n", state_s);
                if (get_value(path_name, uniqi_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, uniqi_s, SEP_EQ_NO_SP, value);
                else if (op->verbose)
                        sgj_pr_hr(jsp, "  %s=?\n", uniqi_s);
                if (get_value(path_name, ubm_s, value, vlen))
                        sgj_haj_vs(jsp, jop, 2, ubm_s, SEP_EQ_NO_SP, value);
        } else if (op->long_opt > 0) {
                n = 0;
                if (get_value(path_name, cpl_s, value, vlen)) {
                        n += sg_scn3pr(b, blen, n, "  %s=%-4s ", cpl_s,
                                       value);
                        if (jsp->pr_as_json)
                                sgj_js_nv_s(jsp, jop, cpl_s, value);
                } else if (op->verbose)
                        n += sg_scn3pr(b, blen, n, "  %s=????\n", cpl_s);

                if (get_value(path_name, hb_s, value, vlen)) {
                        n += sg_scn3pr(b, blen, n, "%s=%-4s ", hb_s, value);
                        if (jsp->pr_as_json)
                                sgj_js_nv_s(jsp, jop, hb_s, value);
                } else if (op->verbose)
                        n += sg_scn3pr(b, blen, n, "%s=????\n", hb_s);

                if (get_value(path_name, sgt_s, value, vlen)) {
                        n += sg_scn3pr(b, blen, n, "%s=%-4s ", sgt_s, value);
                        if (jsp->pr_as_json)
                                sgj_js_nv_s(jsp, jop, sgt_s, value);
                } else if (op->verbose)
                        n += sg_scn3pr(b, blen, n, "%s=????\n", sgt_s);

                if (get_value(path_name, am_s, value, vlen)) {
                        sg_scn3pr(b, blen, n, "%s=%-4s ", am_s, value);
                        if (jsp->pr_as_json)
                                sgj_js_nv_s(jsp, jop, am_s, value);
                }
                sgj_pr_hr(jsp, "%s\n", b);

                if (2 == op->long_opt) {
                        n = 0;
                        if (get_value(path_name, cq_s, value, vlen)) {
                                n += sg_scn3pr(b, blen, n, "  %s=%-4s ", cq_s,
                                               value);
                                if (jsp->pr_as_json)
                                        sgj_js_nv_s(jsp, jop, cq_s, value);
                        }
                        if (get_value(path_name, state_s, value, vlen)) {
                                n += sg_scn3pr(b, blen, n, "  %s=%-8s ",
                                               state_s, value);
                                if (jsp->pr_as_json)
                                        sgj_js_nv_s(jsp, jop, state_s, value);
                        }
                        if (get_value(path_name, uniqi_s, value, vlen)) {
                                n += sg_scn3pr(b, blen, n, "  %s=%-8s ",
                                               uniqi_s, value);
                                if (jsp->pr_as_json)
                                        sgj_js_nv_s(jsp, jop, uniqi_s, value);
                        }
                        if (get_value(path_name, ubm_s, value, vlen)) {
                                sg_scn3pr(b, blen, n, "  %s=%-8s ", ubm_s,
                                          value);
                                if (jsp->pr_as_json)
                                        sgj_js_nv_s(jsp, jop, ubm_s, value);
                        }
                        sgj_pr_hr(jsp, "%s\n", b);
                }
        }
}

static void
one_shost_entry(const char * dir_name, const char * devname,
                struct lsscsi_opts * op, sgj_opaque_p jop)
{
        int n, q;
        unsigned int host_id;
        sgj_state * jsp = &op->json_st;
        char b[LMAX_PATH];
        char value[LMAX_NAME];
        char wd[LMAX_PATH];
        char o[144];
        static const int blen = sizeof(b);
        static const int vlen = sizeof(value);
        static const int olen = sizeof(o);
        static const char * host_id_s = "host_id";

        if (op->classic) {
                // one_classic_host_entry(dir_name, devname, op);
                sgj_pr_hr(jsp, "  <'--classic' not supported for hosts>\n");
                return;
        }
        n = 0;
        q = 0;
        if (1 == sscanf(devname, "host%u", &host_id)) {
                q += sg_scn3pr(o, olen, q, "[%u]", host_id);
                if (jsp->pr_as_json) {
                        sgj_js_nv_s(jsp, jop, lsscsi_loc_s, o);
                        sgj_js_nv_i(jsp, jop, host_id_s, host_id);
                }
                q += sg_scn3pr(o, olen, q, "  ");
        } else
                q += sg_scn3pr(o, olen, q, "[?]  ");
        n += sg_scn3pr(b, blen, n, "%s", dir_name);
        // n += sg_scn3pr(b, blen, n, "%s", "/");
        sg_scn3pr(b, blen, n, "%s", devname);
        if ((get_value(b, "proc_name", value, vlen)) &&
            (strncmp(value, nulln1_s, 6)) && (strncmp(value, nulln2_s, 6))) {
                q += sg_scn3pr(o, olen, q, "  %-12s  ", value);
                if (jsp->pr_as_json)
                        sgj_js_nv_s(jsp, jop, "driver_name", value);
        } else if (if_directory_chdir(b, "device/../driver")) {
                if (NULL == getcwd(wd, sizeof(wd)))
                        q += sg_scn3pr(o, olen, q, "  %-12s  ", nulln2_s);
                else
                        q += sg_scn3pr(o, olen, q, "  %-12s  ", basename(wd));

        } else
                q += sg_scn3pr(o, olen, q, "  proc_name=????  ");
        if (op->transport_info) {
                if (! transport_init(devname, olen - q, o + q)) {
                        if (op->verbose > 3)
                                pr2serr("%s: transport_init() failed\n",
                                        __func__);
                }
                if (jsp->pr_as_json && (strlen(o + q) > 1))
                        sgj_js_nv_s(jsp, jop, "transport_summary", o + q);
        }
        sgj_pr_hr(jsp, "%s\n", o);

        if (op->long_opt > 0)
                longer_sh_entry(b, op, jop);

        if (op->verbose > 0) {
                char b2[LMAX_DEVPATH];
                static const int b2len = sizeof(b2);

                n = sg_scn3pr(b2, b2len, 0, "  dir: %s\n  device dir: ", b);
                if (if_directory_chdir(b, dvc_s)) {
                        if (getcwd(wd, sizeof(wd)))
                                sg_scn3pr(b2, b2len, n, "%s", wd);
                        else
                                sg_scn3pr(b2, b2len, n, "?");
                }
                sgj_pr_hr(jsp, "%s\n", b2);
        }
}

static int
shost_dir_scan_select(const struct dirent * s)
{
        int h;

        if (0 == strncmp("host", s->d_name, 4)) {
                if (filter_active) {
                        if (-1 == filter.h)
                                return 1;
                        else if ((1 == sscanf(s->d_name + 4, "%d", &h) &&
                                 (h == filter.h)))
                                return 1;
                        else
                                return 0;
                } else
                        return 1;
        }
        return 0;
}

/* Returns -1 if (a->d_name < b->d_name) ; 0 if they are equal
 * and 1 otherwise.
 */
static int
shost_scandir_sort(const struct dirent ** a, const struct dirent ** b)
{
        unsigned int l, r;
        const char * lnam = (*a)->d_name;
        const char * rnam = (*b)->d_name;

        if (1 != sscanf(lnam, "host%u", &l))
                return -1;
        if (1 != sscanf(rnam, "host%u", &r))
                return 1;
        if (l < r)
                return -1;
        else if (r < l)
                return 1;
        return 0;
}

static void
list_shosts(struct lsscsi_opts * op, sgj_opaque_p jop)
{
        int num, k;
        struct dirent ** namelist;
        sgj_state * jsp = &op->json_st;
        sgj_opaque_p jo2p = NULL;
        sgj_opaque_p jap = NULL;
        char buff[LMAX_DEVPATH];
        char name[LMAX_NAME];
        static const int namelen = sizeof(name);

        snprintf(buff, sizeof(buff), "%s%s", sysfsroot, scsi_host_s);

        num = scandir(buff, &namelist, shost_dir_scan_select,
                      shost_scandir_sort);
        if (num < 0) {
                int n = 0;

                n += sg_scn3pr(name, namelen, n, "%s: scandir: ", __func__);
                sg_scn3pr(name, namelen, n, "%s", buff);
                perror(name);
                return;
        }
        if (op->classic)
                sgj_pr_hr(jsp, "Attached hosts: %s\n", (num ? "" : none_s));

        if (jsp->pr_as_json) {
                sgj_js_nv_i(jsp, jsp->basep,
                            "number_of_attached_scsi_hosts", num);
                jap = sgj_named_subarray_r(jsp, jop,
                                           "attached_scsi_host_list");
        }
        for (k = 0; k < num; ++k) {
                my_strcopy(name, namelist[k]->d_name, namelen);
                transport_id = TRANSPORT_UNKNOWN;
                jo2p = sgj_new_unattached_object_r(jsp);
                one_shost_entry(buff, name, op, jo2p);
                sgj_js_nv_o(jsp, jap, NULL /* implies an array add */, jo2p);
                free(namelist[k]);
        }
        free(namelist);
}

#if (HAVE_NVME && (! IGNORE_NVME))

/* List NVME hosts (controllers). */
static void
list_nhosts(struct lsscsi_opts * op, sgj_opaque_p jop)
{
        int num, k, n;
        struct dirent ** namelist;
        sgj_state * jsp = &op->json_st;
        sgj_opaque_p jo2p = NULL;
        sgj_opaque_p jap = NULL;
        char buff[LMAX_DEVPATH];
        char ebuf[120];
        static const int blen = sizeof(buff);
        static const int elen = sizeof(ebuf);

        n = sg_scn3pr(buff, blen, 0, "%s", sysfsroot);
        sg_scn3pr(buff, blen, n, "%s", class_nvme);

        num = scandir(buff, &namelist, ndev_dir_scan_select,
                      nhost_scandir_sort);
        if (num < 0) {  /* NVMe module may not be loaded */
                if (op->verbose > 1) {
                        n = sg_scn3pr(ebuf, elen, 0, "%s: scandir: ",
                                      __func__);
                        sg_scn3pr(ebuf, elen, n, "%s", buff);
                        perror(ebuf);
                        sgj_pr_hr(jsp, "NVMe %s\n", mmnbl_s);
                }
                return;
        }
        if (jsp->pr_as_json)
                jap = sgj_named_subarray_r(jsp, jop,
                                           "attached_nvme_controller_list");
        for (k = 0; k < num; ++k) {
                transport_id = TRANSPORT_UNKNOWN;
                if (jsp->pr_as_json)
                        jo2p = sgj_new_unattached_object_r(jsp);
                one_nhost_entry(buff, namelist[k]->d_name, op, jo2p);
                if (jsp->pr_as_json)
                        sgj_js_nv_o(jsp, jap, NULL, jo2p);
                free(namelist[k]);
        }
        free(namelist);
        if (op->wwn)
                free_disk_wwn_node_list();
}

#endif          /* (HAVE_NVME && (! IGNORE_NVME)) */

/* Return true if able to decode, otherwise false */
static bool
one_filter_arg(const char * arg, struct addr_hctl * filtp)
{
        int val, k, n, res;
        uint64_t val64;
        const char * cp;
        const char * cpe;
        char buff[64];

        cp = arg;
        while ((*cp == ' ') || (*cp == '\t') || (*cp == '['))
                ++cp;
        if ('\0' == *cp)
                return true;
        for (k = 0; *cp; cp = cpe + 1, ++k) {
                cpe = strchr(cp, ':');
                if (cpe)
                        n = cpe - cp;
                else {
                        n = strlen(cp);
                        cpe = cp + n - 1;
                }
                val = -1;
                val64 = UINT64_LAST;
                if (n > ((int)sizeof(buff) - 1)) {
                        pr2serr("intermediate string in %s too long (n=%d)\n",
                                arg, n);
                        return false;
                }
                if ((n > 0) && ('-' != *cp) && ('*' != *cp) && ('?' != *cp)) {
                        memcpy(buff, cp, n);
                        buff[n] = '\0';
                        if (3 == k) {
                                if (('0' == buff[0]) &&
                                    ('X' == toupper((uint8_t)buff[1])))
                                        res = sscanf(buff, "%" SCNx64 ,
                                                     &val64);
                                else
                                        res = sscanf(buff, "%" SCNu64 ,
                                                     &val64);
                        } else {
                                res = sscanf(buff, "%d", &val);
                                if ((0 == res) && (0 == k) && (1 == n) &&
                                    ('N' == toupper((uint8_t)buff[0]))) {
                                        /* take 'N' as NVMe indication */
                                        res = 1;
                                        val = NVME_HOST_NUM;
                                }
                        }
                        if ((1 != res) && (NULL == strchr(buff, ']'))) {
                                pr2serr("cannot decode %s as an integer\n",
                                        buff);
                                return false;
                        }
                }
                switch (k) {
                case 0: filtp->h = val;
                        break;
                case 1: filtp->c = val;
                        break;
                case 2: filtp->t = val;
                        break;
                case 3: filtp->l = val64;
                        break;
                default:
                        pr2serr("expect three colons at most in %s\n", arg);
                        return false;
                }
        }
        return true;
}

/* Return true if able to decode, otherwise false */
static bool
decode_filter_arg(const char * a1p, const char * a2p, const char * a3p,
                  const char * a4p, struct addr_hctl * filtp)
{
        int n, rem;
        char * b1p;
        char b1[256];

        if ((NULL == a1p) || (NULL == filtp)) {
                pr2serr("bad call to decode_filter\n");
                return false;
        }
        filtp->h = -1;
        filtp->c = -1;
        filtp->t = -1;
        filtp->l = UINT64_LAST;
        if ((0 == strncmp("host", a1p, 4)) &&
            (1 == sscanf(a1p, "host%d", &n)) && (n >= 0)) {
                filtp->h = n;
                return true;
        }
        if ((NULL == a2p) || strchr(a1p, ':'))
                return one_filter_arg(a1p, filtp);
        else {
                rem = sizeof(b1) - 5;
                b1p = b1;
                if ((n = strlen(a1p)) > rem)
                        goto err_out;
                my_strcopy(b1p, a1p, rem);
                b1p += n;
                *b1p++ = ':';
                rem -= (n + 1);
                if ((n = strlen(a2p)) > rem)
                        goto err_out;
                my_strcopy(b1p, a2p, rem);
                if (a3p) {
                        b1p += n;
                        *b1p++ = ':';
                        rem -= (n + 1);
                        if ((n = strlen(a3p)) > rem)
                                goto err_out;
                        my_strcopy(b1p, a3p, rem);
                        if (a4p) {
                                b1p += n;
                                *b1p++ = ':';
                                rem -= (n + 1);
                                if ((n = strlen(a4p)) > rem)
                                        goto err_out;
                                my_strcopy(b1p, a4p, rem);
                        }
                }
                return one_filter_arg(b1, filtp);
        }
err_out:
        pr2serr("filter arguments exceed internal buffer size (%d)\n",
                (int)sizeof(b1));
        return false;
}

/* Handles short options after '-j' including a sequence of short options
 * that include one 'j' (for JSON). Want optional argument to '-j' to be
 * prefixed by '='. Return 0 for good, 1 for syntax error and 2 for exit
 * with no error. */
static int
chk_short_opts(const char sopt_ch, struct lsscsi_opts * op)
{
        switch (sopt_ch) {
        case 'b':
                op->brief = true;
                break;
        case 'c':
                op->classic = true;
                break;
        case 'C':       /* synonym for --hosts, NVMe perspective */
                op->do_hosts = true;
                break;
        case 'd':
                op->dev_maj_min = true;
                break;
        case 'D':       /* --pdt */
                op->pdt = true;
                break;
        case 'g':
                op->generic = true;
                break;
        case 'h':
                usage();
                return 2;
        case 'H':
                op->do_hosts = true;
                break;
        case 'i':
                if (op->scsi_id)
                        op->scsi_id_twice = true;
                else
                        op->scsi_id = true;
                break;
        case 'j':
                break;  /* simply ignore second 'j' (e.g. '-jxj') */
        case 'k':
                op->kname = true;
                break;
        case 'l':
                ++op->long_opt;
                break;
        case 'L':
                op->long_opt += 3;
                break;
        case 'N':
                op->no_nvme = true;
                break;
        case 'p':
                op->protection = true;
                break;
        case 'P':
                op->protmode = true;
                break;
        case 's':
                ++op->ssize;
                break;
        case 'S':
                op->ssize += 3;
                break;
        case 't':
                op->transport_info = true;
                break;
        case 'u':
                ++op->unit;
                break;
        case 'U':
                op->unit += 3;
                break;
        case 'v':
                ++op->verbose;
                break;
        case 'V':
                ++op->version_count;
                break;
        case 'w':
                if (op->wwn)
                        op->wwn_twice = true;
                else
                        op->wwn = true;
                break;
        case 'x':
                ++op->lunhex;
                break;
        case '?':
                usage();
                return 1;
        default:
                pr2serr("unrecognised option code: '%c' [0x%x]\n\n", sopt_ch,
                        sopt_ch);
                usage();
                return 1;
        }
        return 0;
}


int
main(int argc, char **argv)
{
        bool do_sdevices = true;  /* op->do_hosts checked before this */
        int c;
        int res = 0;
        const char * cp;
        sgj_state * jsp;
        sgj_opaque_p jop = NULL;
        struct lsscsi_opts * op;
        struct lsscsi_opts opts;

        op = &opts;
        cp = getenv("LSSCSI_LUNHEX_OPT");
        invalidate_hctl(&filter);
        memset(op, 0, sizeof(opts));
        while (1) {
                int option_index = 0;

                c = getopt_long(argc, argv,
                                "^bcCdDghHij::J:klLNpPsStuUvVwxy:",
                                long_options, &option_index);
                if (c == -1)
                        break;

                switch (c) {
                case 'b':
                        op->brief = true;
                        break;
                case 'c':
                        op->classic = true;
                        break;
                case 'C':       /* synonym for --hosts, NVMe perspective */
                        op->do_hosts = true;
                        break;
                case 'd':
                        op->dev_maj_min = true;
                        break;
                case 'D':       /* --pdt */
                        op->pdt = true;
                        break;
                case 'g':
                        op->generic = true;
                        break;
                case 'h':
                        usage();
                        return 0;
                case 'H':
                        op->do_hosts = true;
                        break;
                case 'i':
                        if (op->scsi_id)
                                op->scsi_id_twice = true;
                        else
                                op->scsi_id = true;
                        break;
                case 'j':       /* for: -j[=JO] */
                case '^':       /* for: --json[=JO] */
                        op->do_json = true;
                        /* want '=' to precede all JSON optional arguments */
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
                case 'k':
                        op->kname = true;
                        break;
                case 'l':
                        ++op->long_opt;
                        break;
                case 'L':
                        op->long_opt += 3;
                        break;
                case 'N':
                        op->no_nvme = true;
                        break;
                case 'p':
                        op->protection = true;
                        break;
                case 'P':
                        op->protmode = true;
                        break;
                case 's':
                        ++op->ssize;
                        break;
                case 'S':
                        op->ssize += 3;
                        break;
                case 't':
                        op->transport_info = true;
                        break;
                case 'u':
                        ++op->unit;
                        break;
                case 'U':
                        op->unit += 3;
                        break;
                case 'v':
                        ++op->verbose;
                        break;
                case 'V':
                        ++op->version_count;
                        break;
                case 'w':
                        if (op->wwn)
                                op->wwn_twice = true;
                        else
                                op->wwn = true;
                        break;
                case 'x':
                        ++op->lunhex;
                        break;
                case 'y':       /* sysfsroot <dir> */
                        sysfsroot = optarg;
                        break;
                case '?':
                        usage();
                        return 1;
                default:
                        pr2serr("unrecognised option code %c [0x%x]\n", c, c);
                        usage();
                        return 1;
               }
        }
        if (op->version_count > 0) {
                int yr, mon, day;
                char * p;
                char b[64];

                if (1 == op->version_count) {
                        pr2serr("pre-release: %s\n", release_str);
                        return 0;
                }
                cp = strchr(release_str, '/');
                if (cp && (3 == sscanf(cp - 4, "%d/%d/%d", &yr, &mon, &day)))
                        ;
                else {
                        pr2serr("pre-release: %s\n", release_str);
                        return 0;
                }
                strncpy(b, release_str, sizeof(b) - 1);
                p = (char *)strchr(b, '/');
                snprintf(p - 4, sizeof(b) - (p - 4 - b), "%d%02d%02d  ",
                         yr, mon, day);
                b[strlen(b)] = ' ';
                printf("%s\n", b);
                return 0;
        }
        gl_verbose = op->verbose;
        if (op->do_json) {
                if (! sgj_init_state(&op->json_st, op->json_arg)) {
                        int bad_char = op->json_st.first_bad_char;
                        char e[1500];

                        if (bad_char) {
                                pr2serr("bad argument to --json= "
                                        "option, unrecognized "
                                        "character '%c'\n\n",
                                        bad_char);
                         }
                        sg_json_usage(0, e, sizeof(e));
                        pr2serr("%s", e);
                        return 1 /* SG_LIB_SYNTAX_ERROR */;
                }
                /* lsscsi changes directory a lot. If we need the current
                 * working directory later (e.g. to store the JSON output
                 * file) then we need to remember it. */
                if (op->js_file) {
                        if (NULL == getcwd(wd_at_start, sizeof(wd_at_start)))
                                pr2serr("getcwd() failed\n");
                }
        }

        if (optind < argc) {
                const char * a1p = NULL;
                const char * a2p = NULL;
                const char * a3p = NULL;
                const char * a4p = NULL;

                if ((optind + 4) < argc) {
                        pr2serr("unexpected non-option arguments: ");
                        while (optind < argc)
                                pr2serr("%s ", argv[optind++]);
                        pr2serr("\n");
                        return 1;
                }
                a1p = argv[optind++];
                if (optind < argc) {
                        a2p = argv[optind++];
                        if (optind < argc) {
                                a3p = argv[optind++];
                                if (optind < argc)
                                        a4p = argv[optind++];
                        }
                }
                if ((0 == memcmp("host", a1p, 4)) ||
                    (0 == memcmp("HOST", a1p, 4))) {
                        if (! decode_filter_arg(a1p + 4, a2p, a3p, a4p,
                                                &filter))
                                return 1;
                } else {
                        if (! decode_filter_arg(a1p, a2p, a3p, a4p, &filter))
                                return 1;
                }
                if ((filter.h != -1) || (filter.c != -1) ||
                    (filter.t != -1) || (filter.l != UINT64_LAST))
                        filter_active = true;
        }
        if ((0 == op->lunhex) && cp) {
                if (1 == sscanf(cp, "%d", &c))
                        op->lunhex = c;
        }
        if (op->transport_info && op->unit) {
                pr2serr("use '--transport' or '--unit' but not both\n");
                return 1;
        }
        if (op->transport_info &&
            ((1 == op->long_opt) || (2 == op->long_opt))) {
                pr2serr("please use '--list' (rather than '--long') with "
                        "--transport\n");
                return 1;
        }
        if (op->unit) {
                if (op->do_hosts)
                        pr2serr("--unit ignored when --hosts given\n");
                if ((1 == op->long_opt) || (2 == op->long_opt)) {
                        pr2serr("please use '--list' (rather than '--long') "
                                "with --unit\n");
                        return 1;
                }
        }
        if (op->verbose > 1) {
                printf(" sysfsroot: %s\n", sysfsroot);
        }
        jsp = &op->json_st;
        if (op->do_json)
                jop = sgj_start_r("lsscsi", release_str, argc, argv, jsp);
        if (op->do_hosts) {
                list_shosts(op, jop);
#if (HAVE_NVME && (! IGNORE_NVME))
                if ((! op->no_nvme) && (! op->classic))
                        list_nhosts(op, jop);
#endif
        } else if (do_sdevices) {
                list_sdevices(op, jop);
#if (HAVE_NVME && (! IGNORE_NVME))
                if ((! op->no_nvme) && (! op->classic))
                        list_ndevices(op, jop);
#endif
        }
        res = (res >= 0) ? res : 1 /* SG_LIB_CAT_OTHER */;
        if (op->do_json) {
                FILE * fp = stdout;

                /* '--js-file=-' will send JSON output to stdout */
                if (op->js_file) {
                        if ((1 != strlen(op->js_file)) ||
                            ('-' != op->js_file[0])) {
                                /* "w" truncate if exists */
                                if (chdir(wd_at_start) < 0)
                                        perror("failed to cd to wd_at_start");
                                fp = fopen(op->js_file, "w");
                                if (NULL == fp) {
                                        pr2serr("unable to open file: %s\n",
                                                op->js_file);
                                        res = 1 /* SG_LIB_FILE_ERROR */;
                                }
                        }
                }
                if (fp)
                        sgj_js2file_estr(jsp, NULL, res, NULL, fp);
                if (op->js_file && fp && (stdout != fp))
                        fclose(fp);
                sgj_finish(jsp);
        }
        free_dev_node_list();

        return res;
}
#endif
