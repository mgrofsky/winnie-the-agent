"""What the distributions' busybox packages print, recorded from the packages themselves:
the applet list (``busybox --list``) and the usage an applet prints when run without
arguments (after the "BusyBox v... multi-call binary." line and a blank line).

Three generations: 1.30 (Ubuntu 18.04 to 22.04, Debian 10 and 11), 1.35 (Debian 12) and
1.36 (Ubuntu 24.04 on). Ubuntu 18.04 ships 1.27 and is answered as 1.30.
"""

from __future__ import annotations


def generation(version: str) -> str:
    """The table a busybox package version string (``1.30.1 (Ubuntu ...)``) uses."""
    return "1.36" if version >= "1.36" else "1.35" if version >= "1.35" else "1.30"


APPLETS = {
    "1.30": frozenset("""
        [ [[ acpid adjtimex ar arch arp arping ash awk basename bc blkdiscard blockdev brctl
        bunzip2 bzcat bzip2 cal cat chgrp chmod chown chpasswd chroot chvt clear cmp cp cpio
        cttyhack cut date dc dd deallocvt depmod devmem df diff dirname dmesg dnsdomainname
        dos2unix du dumpkmap dumpleases echo egrep env expand expr factor fallocate false
        fatattr fgrep find fold free freeramdisk fsfreeze fstrim ftpget ftpput getopt getty
        grep groups gunzip gzip halt head hexdump hostid hostname httpd hwclock i2cdetect
        i2cdump i2cget i2cset id ifconfig ifdown ifup init insmod ionice ip ipcalc ipneigh
        kill killall klogd last less link linux32 linux64 linuxrc ln loadfont loadkmap
        logger login logname logread losetup ls lsmod lsscsi lzcat lzma lzop md5sum mdev
        microcom mkdir mkdosfs mke2fs mkfifo mknod mkpasswd mkswap mktemp modinfo modprobe
        more mount mt mv nameif nc netstat nl nologin nproc nsenter nslookup nuke od openvt
        partprobe paste patch pidof ping ping6 pivot_root poweroff printf ps pwd rdate
        readlink realpath reboot renice reset resume rev rm rmdir rmmod route rpm rpm2cpio
        run-init run-parts sed seq setkeycodes setpriv setsid sh sha1sum sha256sum sha512sum
        shred shuf sleep sort ssl_client start-stop-daemon stat strings stty svc svok
        swapoff swapon switch_root sync sysctl syslogd tac tail tar taskset tee telnet test
        tftp time timeout top touch tr traceroute traceroute6 true truncate tty ubirename
        udhcpc udhcpd uevent umount uname uncompress unexpand uniq unix2dos unlink unlzma
        unshare unxz unzip uptime usleep uudecode uuencode vconfig vi w watch watchdog wc
        wget which who whoami xargs xxd xz xzcat yes zcat
    """.split()),
    "1.35": frozenset("""
        [ [[ acpid adjtimex ar arch arp arping ascii ash awk base64 basename bc blkdiscard
        blkid blockdev brctl bunzip2 bzcat bzip2 cal cat chgrp chmod chown chroot chvt clear
        cmp cp cpio crc32 cttyhack cut date dc dd deallocvt depmod devmem df diff dirname
        dmesg dnsdomainname dos2unix du dumpkmap dumpleases echo egrep env expand expr
        factor fallocate false fatattr fdisk fgrep find findfs fold free freeramdisk
        fsfreeze fstrim ftpget ftpput getopt getty grep groups gunzip gzip halt head hexdump
        hostid hostname httpd hwclock i2cdetect i2cdump i2cget i2cset i2ctransfer id
        ifconfig ifdown ifup init insmod ionice ip ipcalc ipneigh kill killall klogd last
        less link linux32 linux64 linuxrc ln loadfont loadkmap logger login logname logread
        losetup ls lsmod lsscsi lzcat lzma lzop md5sum mdev microcom mim mkdir mkdosfs
        mke2fs mkfifo mknod mkpasswd mkswap mktemp modinfo modprobe more mount mt mv nameif
        nc netstat nl nologin nproc nsenter nslookup nuke od openvt partprobe paste patch
        pidof ping ping6 pivot_root poweroff printf ps pwd rdate readlink realpath reboot
        renice reset resume rev rm rmdir rmmod route rpm rpm2cpio run-init run-parts sed seq
        setkeycodes setpriv setsid sh sha1sum sha256sum sha3sum sha512sum shred shuf sleep
        sort ssl_client start-stop-daemon stat strings stty svc svok swapoff swapon
        switch_root sync sysctl syslogd tac tail tar taskset tee telnet test tftp time
        timeout top touch tr traceroute traceroute6 true truncate ts tty ubirename udhcpc
        udhcpd uevent umount uname uncompress unexpand uniq unix2dos unlink unlzma unshare
        unxz unzip uptime usleep uudecode uuencode vconfig vi w watch watchdog wc wget which
        who whoami xargs xxd xz xzcat yes zcat
    """.split()),
    "1.36": frozenset("""
        [ [[ acpid adjtimex ar arch arp arping ascii ash awk base64 basename bc blkdiscard
        blkid blockdev brctl bunzip2 bzcat bzip2 cal cat chgrp chmod chown chpasswd chroot
        chvt clear cmp cp cpio crc32 crond crontab cttyhack cut date dc dd deallocvt depmod
        devmem df diff dirname dmesg dnsdomainname dos2unix dpkg dpkg-deb du dumpkmap
        dumpleases echo ed egrep env expand expr factor fallocate false fatattr fdisk fgrep
        find findfs fold free freeramdisk fsfreeze fstrim ftpget ftpput getopt getty grep
        groups gunzip gzip halt head hexdump hostid hostname httpd hwclock i2cdetect i2cdump
        i2cget i2cset i2ctransfer id ifconfig ifdown ifup init insmod ionice ip ipcalc kill
        killall klogd last less link linux32 linux64 linuxrc ln loadfont loadkmap logger
        login logname logread losetup ls lsmod lsscsi lzcat lzma lzop md5sum mdev microcom
        mim mkdir mkdosfs mke2fs mkfifo mknod mkpasswd mkswap mktemp modinfo modprobe more
        mount mt mv nameif nbd-client nc netstat nl nologin nproc nsenter nslookup nuke od
        openvt partprobe passwd paste patch pidof ping ping6 pivot_root poweroff printf ps
        pwd rdate readlink realpath reboot renice reset resume rev rm rmdir rmmod route rpm
        rpm2cpio run-init run-parts sed seq setkeycodes setpriv setsid sh sha1sum sha256sum
        sha3sum sha512sum shred shuf sleep sort ssl_client start-stop-daemon stat strings
        stty su sulogin svc svok swapoff swapon switch_root sync sysctl syslogd tac tail tar
        taskset tc tee telnet test tftp time timeout top touch tr traceroute traceroute6
        true truncate ts tty tunctl ubirename udhcpc udhcpc6 udhcpd uevent umount uname
        uncompress unexpand uniq unix2dos unlink unlzma unshare unxz unzip uptime usleep
        uudecode uuencode vconfig vi w watch watchdog wc wget which who whoami xargs xxd xz
        xzcat yes zcat
    """.split()),
}

USAGE = {
    "1.30": {
        "rmdir": (
            'Usage: rmdir [OPTIONS] DIRECTORY...\n'
            '\n'
            'Remove DIRECTORY if it is empty\n'
            '\n'
            '\t-p\tInclude parents\n'
            '\t--ignore-fail-on-non-empty\n'),
        "wget": (
            'Usage: wget [-c|--continue] [--spider] [-q|--quiet] [-O|--output-document FILE]\n'
            "\t[--header 'header: value'] [-Y|--proxy on/off] [-P DIR]\n"
            '\t[--no-check-certificate]\n'
            '\t[-S|--server-response] [-U|--user-agent AGENT] URL...\n'
            '\n'
            'Retrieve files via HTTP or FTP\n'
            '\n'
            '\t--spider\tOnly check URL existence: $? is 0 if exists\n'
            "\t--no-check-certificate\tDon't validate the server's certificate\n"
            '\t-c\t\tContinue retrieval of aborted transfer\n'
            '\t-q\t\tQuiet\n'
            '\t-P DIR\t\tSave to DIR (default .)\n'
            '\t-S    \t\tShow server response\n'
            "\t-O FILE\t\tSave to FILE ('-' for stdout)\n"
            '\t-U STR\t\tUse STR for User-Agent header\n'
            '\t-Y on/off\tUse proxy\n'),
        "tftp": (
            'Usage: tftp [OPTIONS] HOST [PORT]\n'
            '\n'
            'Transfer a file from/to tftp server\n'
            '\n'
            '\t-l FILE\tLocal FILE\n'
            '\t-r FILE\tRemote FILE\n'
            '\t-g\tGet file\n'
            '\t-p\tPut file\n'
            '\t-b SIZE\tTransfer blocks of SIZE octets\n'),
        "cp": (
            'Usage: cp [OPTIONS] SOURCE... DEST\n'
            '\n'
            'Copy SOURCE(s) to DEST\n'
            '\n'
            '\t-a\tSame as -dpR\n'
            '\t-R,-r\tRecurse\n'
            '\t-d,-P\tPreserve symlinks (default if -R)\n'
            '\t-L\tFollow all symlinks\n'
            '\t-H\tFollow symlinks on command line\n'
            '\t-p\tPreserve file attributes if possible\n'
            '\t-f\tOverwrite\n'
            '\t-i\tPrompt before overwrite\n'
            '\t-l,-s\tCreate (sym)links\n'
            '\t-T\tTreat DEST as a normal file\n'
            '\t-u\tCopy only newer files\n'),
        "chmod": (
            'Usage: chmod [-Rcvf] MODE[,MODE]... FILE...\n'
            '\n'
            'Each MODE is one or more of the letters ugoa, one of the\n'
            'symbols +-= and one or more of the letters rwxst\n'
            '\n'
            '\t-R\tRecurse\n'
            '\t-c\tList changed files\n'
            '\t-v\tList all files\n'
            '\t-f\tHide errors\n'),
        "rm": (
            'Usage: rm [-irf] FILE...\n'
            '\n'
            'Remove (unlink) FILEs\n'
            '\n'
            '\t-i\tAlways prompt before removing\n'
            '\t-f\tNever prompt\n'
            '\t-R,-r\tRecurse\n'),
        "mkdir": (
            'Usage: mkdir [OPTIONS] DIRECTORY...\n'
            '\n'
            'Create DIRECTORY\n'
            '\n'
            '\t-m MODE\tMode\n'
            '\t-p\tNo error if exists; make parent directories as needed\n'),
        "mv": (
            'Usage: mv [-fin] SOURCE DEST\n'
            'or: mv [-fin] SOURCE... DIRECTORY\n'
            '\n'
            'Rename SOURCE to DEST, or move SOURCE(s) to DIRECTORY\n'
            '\n'
            "\t-f\tDon't prompt before overwriting\n"
            '\t-i\tInteractive, prompt before overwrite\n'
            "\t-n\tDon't overwrite an existing file\n"),
        "touch": (
            'Usage: touch [-c] [-d DATE] [-t DATE] [-r FILE] FILE...\n'
            '\n'
            'Update the last-modified date on the given FILE[s]\n'
            '\n'
            "\t-c\tDon't create files\n"
            "\t-h\tDon't follow links\n"
            '\t-d DT\tDate/time to use\n'
            '\t-t DT\tDate/time to use\n'
            "\t-r FILE\tUse FILE's date/time\n"),
        "printf": (
            'Usage: printf FORMAT [ARG]...\n'
            '\n'
            'Format and print ARG(s) according to FORMAT (a-la C printf)\n'),
        "nc": (
            'Usage: nc [-iN] [-wN] [-l] [-p PORT] [-f FILE|IPADDR PORT] [-e PROG]\n'
            '\n'
            'Open a pipe to IP:PORT or FILE\n'
            '\n'
            '\t-l\tListen mode, for inbound connects\n'
            '\t\t(use -ll with -e for persistent server)\n'
            '\t-p PORT\tLocal port\n'
            '\t-w SEC\tConnect timeout\n'
            '\t-i SEC\tDelay interval for lines sent\n'
            '\t-f FILE\tUse file (ala /dev/ttyS0) instead of network\n'
            '\t-e PROG\tRun PROG after connect\n'),
        "ftpget": (
            'Usage: ftpget [OPTIONS] HOST [LOCAL_FILE] REMOTE_FILE\n'
            '\n'
            'Download a file via FTP\n'
            '\n'
            '\t-c\tContinue previous transfer\n'
            '\t-v\tVerbose\n'
            '\t-u USER\tUsername\n'
            '\t-p PASS\tPassword\n'
            '\t-P NUM\tPort\n'),
        "ftpput": (
            'Usage: ftpput [OPTIONS] HOST [REMOTE_FILE] LOCAL_FILE\n'
            '\n'
            'Upload a file to a FTP server\n'
            '\n'
            '\t-v\tVerbose\n'
            '\t-u USER\tUsername\n'
            '\t-p PASS\tPassword\n'
            '\t-P NUM\tPort number\n'),
    },
    "1.35": {
        "wget": (
            'Usage: wget [-cqS] [--spider] [-O FILE] [-o LOGFILE] [--header STR]\n'
            '\t[--post-data STR | --post-file FILE] [-Y on/off]\n'
            '\t[--no-check-certificate] [-P DIR] [-U AGENT] URL...\n'
            '\n'
            'Retrieve files via HTTP or FTP\n'
            '\n'
            '\t--spider\tOnly check URL existence: $? is 0 if exists\n'
            "\t--header STR\tAdd STR (of form 'header: value') to headers\n"
            '\t--post-data STR\tSend STR using POST method\n'
            '\t--post-file FILE\tSend FILE using POST method\n'
            "\t--no-check-certificate\tDon't validate the server's certificate\n"
            '\t-c\t\tContinue retrieval of aborted transfer\n'
            '\t-q\t\tQuiet\n'
            '\t-P DIR\t\tSave to DIR (default .)\n'
            '\t-S    \t\tShow server response\n'
            "\t-O FILE\t\tSave to FILE ('-' for stdout)\n"
            '\t-o LOGFILE\tLog messages to FILE\n'
            '\t-U STR\t\tUse STR for User-Agent header\n'
            '\t-Y on/off\tUse proxy\n'),
    },
    "1.36": {
        "rmdir": (
            'Usage: rmdir [-p] DIRECTORY...\n'
            '\n'
            'Remove DIRECTORY if it is empty\n'
            '\n'
            '\t-p\tInclude parents\n'
            '\t--ignore-fail-on-non-empty\n'),
        "wget": (
            'Usage: wget [-cqS] [--spider] [-O FILE] [-o LOGFILE] [--header STR]\n'
            '\t[--post-data STR | --post-file FILE] [-Y on/off]\n'
            '\t[--no-check-certificate] [-P DIR] [-U AGENT] [-T SEC] URL...\n'
            '\n'
            'Retrieve files via HTTP or FTP\n'
            '\n'
            '\t--spider\tOnly check URL existence: $? is 0 if exists\n'
            "\t--header STR\tAdd STR (of form 'header: value') to headers\n"
            '\t--post-data STR\tSend STR using POST method\n'
            '\t--post-file FILE\tSend FILE using POST method\n'
            "\t--no-check-certificate\tDon't validate the server's certificate\n"
            '\t-c\t\tContinue retrieval of aborted transfer\n'
            '\t-q\t\tQuiet\n'
            '\t-P DIR\t\tSave to DIR (default .)\n'
            '\t-S    \t\tShow server response\n'
            '\t-T SEC\t\tNetwork read timeout is SEC seconds\n'
            "\t-O FILE\t\tSave to FILE ('-' for stdout)\n"
            '\t-o LOGFILE\tLog messages to FILE\n'
            '\t-U STR\t\tUse STR for User-Agent header\n'
            '\t-Y on/off\tUse proxy\n'),
        "tftp": (
            'Usage: tftp [OPTIONS] HOST [PORT]\n'
            '\n'
            'Transfer a file from/to tftp server\n'
            '\n'
            '\t-l FILE\tLocal FILE\n'
            '\t-r FILE\tRemote FILE\n'
            '\t-g\tGet file\n'
            '\t-p\tPut file\n'
            '\t-b SIZE\tTransfer blocks in bytes\n'),
        "cp": (
            'Usage: cp [-arPLHpfinlsTu] SOURCE DEST\n'
            'or: cp [-arPLHpfinlsu] SOURCE... { -t DIRECTORY | DIRECTORY }\n'
            '\n'
            'Copy SOURCEs to DEST\n'
            '\n'
            '\t-a\tSame as -dpR\n'
            '\t-R,-r\tRecurse\n'
            '\t-d,-P\tPreserve symlinks (default if -R)\n'
            '\t-L\tFollow all symlinks\n'
            '\t-H\tFollow symlinks on command line\n'
            '\t-p\tPreserve file attributes if possible\n'
            '\t-f\tOverwrite\n'
            '\t-i\tPrompt before overwrite\n'
            "\t-n\tDon't overwrite\n"
            '\t-l,-s\tCreate (sym)links\n'
            '\t-T\tRefuse to copy if DEST is a directory\n'
            '\t-t DIR\tCopy all SOURCEs into DIR\n'
            '\t-u\tCopy only newer files\n'),
        "chmod": (
            'Usage: chmod [-Rcvf] MODE[,MODE]... FILE...\n'
            '\n'
            'MODE is octal number (bit pattern sstrwxrwxrwx) or [ugoa]{+|-|=}[rwxXst]\n'
            '\n'
            '\t-R\tRecurse\n'
            '\t-c\tList changed files\n'
            '\t-v\tVerbose\n'
            '\t-f\tHide errors\n'),
        "rm": (
            'Usage: rm [-irf] FILE...\n'
            '\n'
            'Remove (unlink) FILEs\n'
            '\n'
            '\t-i\tAlways prompt before removing\n'
            '\t-f\tNever prompt\n'
            '\t-R,-r\tRecurse\n'),
        "mkdir": (
            'Usage: mkdir [-m MODE] [-p] DIRECTORY...\n'
            '\n'
            'Create DIRECTORY\n'
            '\n'
            '\t-m MODE\tMode\n'
            '\t-p\tNo error if exists; make parent directories as needed\n'),
        "mv": (
            'Usage: mv [-finT] SOURCE DEST\n'
            'or: mv [-fin] SOURCE... { -t DIRECTORY | DIRECTORY }\n'
            '\n'
            'Rename SOURCE to DEST, or move SOURCEs to DIRECTORY\n'
            '\n'
            "\t-f\tDon't prompt before overwriting\n"
            '\t-i\tInteractive, prompt before overwrite\n'
            "\t-n\tDon't overwrite an existing file\n"
            '\t-T\tRefuse to move if DEST is a directory\n'
            '\t-t DIR\tMove all SOURCEs into DIR\n'),
        "touch": (
            'Usage: touch [-cham] [-d DATE] [-t DATE] [-r FILE] FILE...\n'
            '\n'
            'Update mtime of FILEs\n'
            '\n'
            "\t-c\tDon't create files\n"
            "\t-h\tDon't follow links\n"
            '\t-a\tChange only atime\n'
            '\t-m\tChange only mtime\n'
            '\t-d DT\tDate/time to use\n'
            '\t-t DT\tDate/time to use\n'
            "\t-r FILE\tUse FILE's date/time\n"),
        "printf": (
            'Usage: printf FORMAT [ARG]...\n'
            '\n'
            'Format and print ARG(s) according to FORMAT (a-la C printf)\n'),
        "nc": (
            'Usage: nc [-iN] [-wN] [-l] [-p PORT] [-f FILE|IPADDR PORT] [-e PROG]\n'
            '\n'
            'Open a pipe to IP:PORT or FILE\n'
            '\n'
            '\t-l\tListen mode, for inbound connects\n'
            '\t\t(use -ll with -e for persistent server)\n'
            '\t-p PORT\tLocal port\n'
            '\t-w SEC\tConnect timeout\n'
            '\t-i SEC\tDelay interval for lines sent\n'
            '\t-f FILE\tUse file (ala /dev/ttyS0) instead of network\n'
            '\t-e PROG\tRun PROG after connect\n'),
        "ftpget": (
            'Usage: ftpget [OPTIONS] HOST [LOCAL_FILE] REMOTE_FILE\n'
            '\n'
            'Download a file via FTP\n'
            '\n'
            '\t-c\tContinue previous transfer\n'
            '\t-v\tVerbose\n'
            '\t-u USER\tUsername\n'
            '\t-p PASS\tPassword\n'
            '\t-P PORT\n'),
        "ftpput": (
            'Usage: ftpput [OPTIONS] HOST [REMOTE_FILE] LOCAL_FILE\n'
            '\n'
            'Upload a file to a FTP server\n'
            '\n'
            '\t-v\tVerbose\n'
            '\t-u USER\tUsername\n'
            '\t-p PASS\tPassword\n'
            '\t-P PORT\n'),
    },
}
# Debian 12 prints what Ubuntu 24.04 prints except where listed above.
USAGE["1.35"] = {**USAGE["1.36"], **USAGE["1.35"]}
