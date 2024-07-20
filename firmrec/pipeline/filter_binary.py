#!python
import sys
import os
import stat
import json
import argparse

from firmlib import get_strings_from_bin, get_all_files, is_elf


UPDATE = os.getenv("UPDATE", "0") == "1"
VERSION_ANALYSIS = os.getenv("VERSION_ANALYSIS", "0") == "1"


NETWORK_KEYWORDS = [
    "QUERY_STRING",
    "username",
    "http_",
    "REMOTE_ADDR",
    "boundary=",
    "HTTP_",
    "query",
    "remote",
    "user-agent",
    "soap",
    "SOAP",
    "index.",
    "CONTENT_TYPE",
    "Content-Type",
    "parse",
    "Parse",
    "packet",
    "Packet",
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "HEAD",
    "auth",
    "AUTH",
]


def find_keywords_from_bin(bin_path, keywords):
    hit_keywords = set()
    # Stash for performance
    length_stash = [[], [], [], [], []]  # 0-4, 5-9, 10-15, 16-31, 32+

    def get_stash(s):
        s_length = len(s)
        if s_length < 5:
            return length_stash[0]
        elif s_length < 10:
            return length_stash[1]
        elif s_length < 16:
            return length_stash[2]
        elif s_length < 32:
            return length_stash[3]
        else:
            return length_stash[4]

    bin_strings = get_strings_from_bin(bin_path, min_len=3, allow_space=False)
    for bin_string in bin_strings:
        get_stash(bin_string).append(bin_string)

    for keyword in keywords:
        stash = get_stash(keyword)
        for string_candidate in stash:
            if string_candidate.find(keyword) != -1:
                hit_keywords.add(keyword)
                break
    return bin_strings, hit_keywords


def filter_binary(unpacked_dir, keywords, filter_func):
    # We currently rely on front end keywords to location input locations.
    # So we simply ignore firmwares where no keyword was found.
    if not keywords:
        return {"paths": [], "keywords": {}}
    all_files = get_all_files(unpacked_dir)
    result = {
        "paths": [],
        "target_paths": [],
        "keywords": {},
    }
    
    print("Expected keywords", keywords)

    for b_path in all_files:
        dir_white_list = [
            "/private/",
        ]

        bin_white_list = [
            "libcmm.so",
            "httpd",
            "cgi",
            "upnp",
            "boa",
            "dhcp",
            "hostap",
        ]

        is_lib = (
            b_path.endswith(".so")
            or b_path.endswith(".ko")
            or b_path.endswith(".o")
            or ".so." in b_path
            or ".ko." in b_path
            or ".o." in b_path
        )

        if (
            any(s in os.path.basename(b_path) for s in bin_white_list)
            or any(s in b_path for s in dir_white_list)
        ) and not is_lib:
            white_listed = True
        else:
            white_listed = False

        if not white_listed:
            if is_lib:
                continue

        # ignore common command line utilities
        if os.path.basename(b_path) in common_bin_names:
            continue

        if not is_elf(b_path):
            continue
        print("Consider", b_path)
        bin_strings, hit_keywords = find_keywords_from_bin(b_path, keywords)
        print("Hit keywords", hit_keywords)

        # try:
        #     if b_path.endswith("d"):
        #         import r2pipe
        #         r2 = r2pipe.open(b_path)
        #         symbols = r2.cmdj("isj")
        #         r2.quit()
        #         symbol_names = {symbol['realname'] for symbol in symbols}
        #         for raw_func in ['accept', 'recv', 'recvfrom', 'select']:
        #             if raw_func in symbol_names:
        #                 hit_keywords.add(raw_func)
        # except: # pylint: disable=bare-except
        #     pass

        bin_rel_path = os.path.relpath(b_path, unpacked_dir)
        result["paths"].append(bin_rel_path)
        if bin_rel_path not in result["keywords"]:
            result["keywords"][bin_rel_path] = list(hit_keywords)

    filter_func(result)

    return result


def filter_binary_update(output_path):
    """filter binary by keyword frequency"""
    with open(output_path, "r", encoding="utf-8") as f:
        result = json.load(f)

    result["target_paths"] = []
    filter_binary_by_keyword(result)
    return result


def filter_vuln_binary_by_keyword(result):
    """Filter vulnerable"""

    target_paths = []
    for path, hit_keywords in result["keywords"].items():
        if not hit_keywords:
            continue
        target_paths.append(path)

    result["target_paths"] = target_paths

    print(len(result["paths"]), "paths: ", result["paths"])
    print(len(target_paths), "target paths: ", target_paths)


def filter_binary_by_keyword(result):
    """filter binary by keyword frequency"""
    keyword_freq = {}

    for _, hit_keywords in result["keywords"].items():
        for keyword in hit_keywords:
            if keyword not in keyword_freq:
                keyword_freq[keyword] = 0
            keyword_freq[keyword] += 1

    path_score = {}
    for path, hit_keywords in result["keywords"].items():
        path_score[path] = 0
        for keyword in hit_keywords:
            path_score[path] += 1.0 / keyword_freq[keyword]
        if path.endswith("d"):  # usually daemon service
            path_score[path] += 0.2

    sorted_paths = sorted(result["paths"], key=lambda x: path_score[x], reverse=True)
    # select top 10 paths or less if meet same score
    target_paths = result["target_paths"]
    target_paths.clear()
    prev_score = -1

    for path in sorted_paths:
        if len(target_paths) >= 10:
            break
        if prev_score > 0 and prev_score < 3 and prev_score - path_score[path] < 0.3:
            break
        prev_score = path_score[path]
        target_paths.append(path)

    whilte_list = [
        "cgibin",
        "goahead",
        "boa",
        "acos_service",
        "rc",
        # Known Daemons
        "httpd",
        "mini_httpd",
        "upnpd",
        "dhcpd",
        "udhcpd",
        "hostapd",
        "pppd",
        "wscd",
    ]
    for path in set(result["paths"]) - set(target_paths):
        if (
            path.endswith("cgi")
            or "cgi" in path.split("/")
            or path.endswith(".so")
            or path.split("/")[-1] in whilte_list
        ):
            target_paths.append(path)

    result["path_score"] = [[path, path_score[path]] for path in sorted_paths]
    result["paths"] = sorted_paths
    print(len(result["paths"]), "paths: ", result["paths"])
    print(len(target_paths), "target paths: ", target_paths)

    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("unpacked_dir", type=str, help="unpacked firmware directory")
    parser.add_argument("keywords_file", type=str, help="keywords file")
    parser.add_argument("out_file", type=str, help="output file")
    parser.add_argument("--update", action="store_true", help="update the result file")
    parser.add_argument(
        "--vuln-info", type=str, help="filter binary for vulnerability analysis"
    )
    args = parser.parse_args()

    unpacked_dir = args.unpacked_dir
    keywords_file = args.keywords_file
    output_path = args.out_file

    result = None
    if args.vuln_info:
        vuln_info = json.load(open(args.vuln_info, "r", encoding="utf-8"))
        if "kv" in vuln_info["input"]:
            expected_keywords = set(vuln_info["input"]["kv"])
            result = filter_binary(
                unpacked_dir, expected_keywords, filter_vuln_binary_by_keyword
            )

    if args.update:
        result = filter_binary_update(output_path)
    elif not result:
        expected_keywords = set(json.load(open(keywords_file, "r", encoding="utf-8")))
        expected_keywords.union(set(NETWORK_KEYWORDS))
        result = filter_binary(
            unpacked_dir, expected_keywords, filter_binary_by_keyword
        )

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w+", encoding="utf-8") as f:
        json.dump(result, f)

    # for p in filtered_paths:
    #     print(p)


common_bin_names = [
    "adb",
    "adbd",
    "acpid",
    "addgroup",
    "addpart",
    "addr2line",
    "add-shell",
    "adduser",
    "agetty",
    "alsactl",
    "alsamixer",
    "aplay",
    "ar",
    "arecord",
    "arptables",
    "as",
    "atd",
    "attr",
    "avahi-autoipd",
    "avahi-browse",
    "avahi-browse-domains",
    "avahi-daemon",
    "avahi-publish",
    "avahi-publish-address",
    "avahi-publish-service",
    "avahi-resolve",
    "avahi-resolve-address",
    "avahi-resolve-host-name",
    "avahi-set-host-name",
    "awk",
    "badblocks",
    "base64",
    "basename",
    "bash",
    "bc",
    "bccmd",
    "bcrelay",
    "blkdiscard",
    "blkid",
    "blockdev",
    "bluetoothctl",
    "bluetoothd",
    "brctl",
    "bridge",
    "btmgmt",
    "btmon",
    "bunzip2",
    "busybox",
    "bzcat",
    "bzip2",
    "cal",
    "cat",
    "cfdisk",
    "c++filt",
    "chacl",
    "chage",
    "chat",
    "chattr",
    "chgpasswd",
    "chgrp",
    "chmod",
    "chown",
    "chpasswd",
    "chroot",
    "chrt",
    "chvt",
    "ciptool",
    "cksum",
    "clear",
    "cmp",
    "col",
    "colcrt",
    "colrm",
    "column",
    "comm",
    "cp",
    "cpio",
    "crda",
    "cron",
    "crontab",
    "cryptsetup",
    "ctrlaltdel",
    "cupsd",
    "curl",
    "cut",
    "date",
    "dbus-cleanup-sockets",
    "dbus-daemon",
    "dbus-launch",
    "dbus-monitor",
    "dbus-run-session",
    "dbus-send",
    "dbus-uuidgen",
    "dc",
    "dd",
    "deallocvt",
    "debugfs",
    "delgroup",
    "delpart",
    "deluser",
    "depmod",
    "df",
    "dhclient",
    "diff",
    "dirname",
    "dmesg",
    "dmsetup",
    "dmstats",
    "dnsdomainname",
    "dnsmasq",
    "dosfsck",
    "du",
    "dumpe2fs",
    "dumpkeys",
    "e2fsck",
    "e2image",
    "e2label",
    "e2undo",
    "e4crypt",
    "e4defrag",
    "ebtables",
    "ebtables-restore",
    "echo",
    "ed",
    "egrep",
    "eject",
    "elfedit",
    "env",
    "ethtool",
    "expand",
    "expiry",
    "expr",
    "faillog",
    "fallocate",
    "false",
    "fatlabel",
    "fc",
    "fdformat",
    "fdisk",
    "fgconsole",
    "fgrep",
    "filefrag",
    "find",
    "findfs",
    "findmnt",
    "flashcp",
    "flash_erase",
    "flash_eraseall",
    "flash_lock",
    "flash_otp_dump",
    "flash_otp_info",
    "flash_unlock",
    "flock",
    "fold",
    "free",
    "fsck",
    "fsck.cramfs",
    "fsck.ext2",
    "fsck.ext3",
    "fsck.ext4",
    "fsck.fat",
    "fsck.minix",
    "fsfreeze",
    "fstrim",
    "ftl_check",
    "ftl_format",
    "ftp",
    "funzip",
    "fuser",
    "fusermount",
    "gatttool",
    "gdb",
    "gdbserver",
    "gdbus",
    "getfacl",
    "getfattr",
    "getkeycodes",
    "getopt",
    "getty",
    "glib-compile-resources",
    "glib-compile-schemas",
    "glib-genmarshal",
    "gpasswd",
    "gpg",
    "gpgv",
    "gprof",
    "grep",
    "gresource",
    "groupadd",
    "groupdel",
    "groupmems",
    "groupmod",
    "groups",
    "grpck",
    "grpconv",
    "grpunconv",
    "gsettings",
    "gtester",
    "gunzip",
    "gzip",
    "halt",
    "hciattach",
    "hcitool",
    "hd",
    "hdparm",
    "head",
    "hexdump",
    "hostid",
    "hostname",
    "hostnamectl",
    "hwclock",
    "iconv",
    "id",
    "init",
    "insmod",
    "install",
    "ionice",
    "iostat",
    "ip",
    "ip6tables",
    "ip6tables-restore",
    "ip6tables-save",
    "ipcmk",
    "ipcrm",
    "ipcs",
    "iptables",
    "iptables-restore",
    "iptables-save",
    "iptables-xml",
    "isosize",
    "iw",
    "iwconfig",
    "iwevent",
    "iwgetid",
    "iwlist",
    "iwpriv",
    "iwspy",
    "journalctl",
    "kbdinfo",
    "kbd_mode",
    "kbdrate",
    "kill",
    "killall",
    "killall5",
    "kmod",
    "l2test",
    "last",
    "lastlog",
    "ldattach",
    "ldd",
    "less",
    "linux32",
    "linux64",
    "ln",
    "loadkeys",
    "loadunimap",
    "localectl",
    "logger",
    "login",
    "loginctl",
    "logname",
    "logrotate",
    "logsave",
    "look",
    "losetup",
    "lowntfs-3g",
    "lpadmin",
    "ls",
    "lsattr",
    "lsblk",
    "lscpu",
    "lslocks",
    "lsmod",
    "lsof",
    "lspci",
    "lsusb",
    "lvm",
    "lzcat",
    "lzma",
    "lzop",
    "make",
    "mapscrn",
    "mcookie",
    "md5sum",
    "mdadm",
    "mesg",
    "mkdir",
    "mkdosfs",
    "mke2fs",
    "mkfifo",
    "mkfs",
    "mkfs.bfs",
    "mkfs.cramfs",
    "mkfs.ext2",
    "mkfs.ext3",
    "mkfs.ext4",
    "mkfs.fat",
    "mkfs.jffs2",
    "mkfs.minix",
    "mkfs.ubifs",
    "mkfs.vfat",
    "mkfs.xfs",
    "mklost+found",
    "mknod",
    "mkntfs",
    "mkswap",
    "mktemp",
    "mlabel",
    "modinfo",
    "modprobe",
    "more",
    "mount",
    "mountpoint",
    "mpstat",
    "mt",
    "mtd_debug",
    "mtdinfo",
    "mtdpart",
    "mtools",
    "mtr",
    "mv",
    "namei",
    "nanddump",
    "nandtest",
    "nandwrite",
    "nano",
    "nc",
    "net",
    "newusers",
    "nftldump",
    "nftl_format",
    "nice",
    "nm",
    "nmbd",
    "nmblookup",
    "nohup",
    "nologin",
    "nsenter",
    "nslookup",
    "ntfs-3g",
    "ntfs-3g.probe",
    "ntfsinfo",
    "ntfslabel",
    "objcopy",
    "objdump",
    "od",
    "openssl",
    "openvpn",
    "openvt",
    "parted",
    "partprobe",
    "partx",
    "passwd",
    "patch",
    "pdbedit",
    "pgrep",
    "pidof",
    "pidstat",
    "ping",
    "ping6",
    "pivot_root",
    "pkill",
    "pmap",
    "poweroff",
    "pppoe-discovery",
    "pptp",
    "pptpctrl",
    "pptpd",
    "printenv",
    "printf",
    "prlimit",
    "ps",
    "psfxtable",
    "pstree",
    "pwck",
    "pwconv",
    "pwd",
    "pwdx",
    "pwunconv",
    "raw",
    "rctest",
    "readelf",
    "readlink",
    "readprofile",
    "realpath",
    "reboot",
    "redis-cli",
    "redis-server",
    "renice",
    "reset",
    "rev",
    "rfcomm",
    "rm",
    "rmdir",
    "rmmod",
    "rmt",
    "rtcwake",
    "rtmon",
    "runlevel",
    "run-parts",
    "runuser",
    "sadf",
    "sar",
    "sched",
    "scp",
    "script",
    "scriptreplay",
    "sdptool",
    "sed",
    "seq",
    "service",
    "setarch",
    "setfacl",
    "setfattr",
    "setfont",
    "setkeycodes",
    "setleds",
    "setlogcons",
    "setmetamode",
    "setpci",
    "setsid",
    "setterm",
    "setvtrgb",
    "sfdisk",
    "sgdisk",
    "sh",
    "sha1sum",
    "sha256sum",
    "sha512sum",
    "showconsolefont",
    "showkey",
    "shuf",
    "size",
    "skill",
    "slabtop",
    "sleep",
    "smbcontrol",
    "smbd",
    "smbpasswd",
    "smbstatus",
    "snice",
    "sort",
    "split",
    "sqldiff",
    "sqlite3",
    "ssh",
    "sshd",
    "start-stop-daemon",
    "stat",
    "strace",
    "strings",
    "strip",
    "stty",
    "su",
    "sulogin",
    "sum",
    "swaplabel",
    "swapoff",
    "swapon",
    "switch_root",
    "sync",
    "sysctl",
    "systemctl",
    "systemd",
    "systemd-ask-password",
    "systemd-cat",
    "systemd-cgls",
    "systemd-cgtop",
    "systemd-delta",
    "systemd-detect-virt",
    "systemd-escape",
    "systemd-hwdb",
    "systemd-inhibit",
    "systemd-machine-id-setup",
    "systemd-notify",
    "systemd-path",
    "systemd-run",
    "systemd-socket-activate",
    "systemd-stdio-bridge",
    "systemd-sysusers",
    "systemd-tmpfiles",
    "systemd-tty-ask-password-agent",
    "tac",
    "tail",
    "tar",
    "taskset",
    "tc",
    "tcpdump",
    "tdbdump",
    "tee",
    "telnet",
    "test",
    "testparm",
    "thermald",
    "time: shell reserved word",
    "timedatectl",
    "timeout",
    "tload",
    "top",
    "touch",
    "tput",
    "tr",
    "traceroute6",
    "tree",
    "true",
    "truncate",
    "tset",
    "tty",
    "tune2fs",
    "ubiattach",
    "ubiblock",
    "ubicrc32",
    "ubidetach",
    "ubiformat",
    "ubimkvol",
    "ubinfo",
    "ubinize",
    "ubirename",
    "ubirmvol",
    "ubirsvol",
    "ubiupdatevol",
    "udevadm",
    "ul",
    "umount",
    "uname",
    "uncompress",
    "unexpand",
    "uniq",
    "unix_chkpwd",
    "unix_update",
    "unlink",
    "unlzma",
    "unshare",
    "unxz",
    "unzip",
    "unzipsfx",
    "uptime",
    "usbhid-dump",
    "usb_modeswitch",
    "usbreset",
    "useradd",
    "userdel",
    "usermod",
    "users",
    "utmpdump",
    "uuidd",
    "uuidgen",
    "vi",
    "vim",
    "vmstat",
    "w",
    "wall",
    "watch",
    "wc",
    "wdctl",
    "wget",
    "whereis",
    "which",
    "who",
    "whoami",
    "wipefs",
    "wpa_cli",
    "wpa_passphrase",
    "wpa_supplicant",
    "write",
    "xargs",
    "xfs_db",
    "xfs_growfs",
    "xfs_repair",
    "xl2tpd",
    "xl2tpd-control",
    "xmlcatalog",
    "xmllint",
    "xtables-legacy-multi",
    "xz",
    "xzcat",
    "yes",
    "zcat",
    "zic",
    "zip",
    "zipcloak",
    "zipinfo",
    "zipnote",
    "zipsplit",
    "[",
    "[[",
]


if __name__ == "__main__":
    main()
