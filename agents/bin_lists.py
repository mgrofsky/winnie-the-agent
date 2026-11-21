"""The base system's /usr/bin and /usr/sbin (where /bin and /sbin point), as each
distribution's minimal image lists them. ``agents.shell`` adds the programs its host
profile has on top (``Host.bins``), so a listing agrees with what the shell answers.
"""

from __future__ import annotations


def _names(text: str) -> tuple[str, ...]:
    return tuple(text.split())


BIN_UBUNTU_22 = _names("""
[ addpart apt apt-cache apt-cdrom apt-config apt-get apt-key apt-mark arch awk b2sum base32
base64 basename basenc bash bashbug captoinfo cat chage chattr chcon chfn chgrp chmod choom
chown chrt chsh cksum clear clear_console cmp comm cp csplit cut dash date dd deb-systemd-
helper deb-systemd-invoke debconf debconf-apt-progress debconf-communicate debconf-copydb
debconf-escape debconf-set-selections debconf-show delpart df diff diff3 dir dircolors
dirname dmesg dnsdomainname domainname dpkg dpkg-deb dpkg-divert dpkg-maintscript-helper
dpkg-query dpkg-realpath dpkg-split dpkg-statoverride dpkg-trigger du echo egrep env expand
expiry expr factor faillog fallocate false fgrep fincore find findmnt flock fmt fold free
getconf getent getopt gpasswd gpgv grep groups gunzip gzexe gzip hardlink head hostid
hostname iconv id infocmp infotocap install ionice ipcmk ipcrm ipcs ischroot join kill last
lastb lastlog ldd link linux32 linux64 ln locale locale-check localedef logger login logname
ls lsattr lsblk lscpu lsipc lslocks lslogins lsmem lsns man mawk mcookie md5sum
md5sum.textutils mesg mkdir mkfifo mknod mktemp more mount mountpoint mv namei nawk newgrp
nice nisdomainname nl nohup nproc nsenter numfmt od pager partx passwd paste pathchk perl
perl5.34.0 pgrep pidof pidwait pinky pkill pldd pmap pr printenv printf prlimit ps ptx pwd
pwdx rbash readlink realpath renice reset resizepart rev rgrep rm rmdir run-parts runcon
savelog script scriptlive scriptreplay sdiff sed select-editor sensible-browser sensible-
editor sensible-pager seq setarch setpriv setsid setterm sg sh sha1sum sha224sum sha256sum
sha384sum sha512sum shred shuf skill slabtop sleep snice sort split stat stdbuf stty su sum
sync tabs tac tail tar taskset tee tempfile test tic timeout tload toe top touch tput tr
true truncate tset tsort tty tzselect uclampset umount uname uncompress unexpand uniq unlink
unshare update-alternatives uptime users utmpdump vdir vmstat w wall watch wc wdctl whereis
which which.debianutils who whoami xargs yes ypdomainname zcat zcmp zdiff zdump zegrep
zfgrep zforce zgrep zless zmore znew
""")
SBIN_UBUNTU_22 = _names("""
add-shell addgroup adduser agetty badblocks blkdiscard blkid blkzone blockdev chcpu
chgpasswd chmem chpasswd chroot cpgr cppw ctrlaltdel debugfs delgroup deluser dpkg-
preconfigure dpkg-reconfigure dumpe2fs e2freefrag e2fsck e2image e2label e2mmpstatus e2scrub
e2scrub_all e2undo e4crypt e4defrag faillock filefrag findfs fsck fsck.cramfs fsck.ext2
fsck.ext3 fsck.ext4 fsck.minix fsfreeze fstab-decode fstrim getty groupadd groupdel
groupmems groupmod grpck grpconv grpunconv hwclock iconvconfig initctl installkernel invoke-
rc.d isosize killall5 ldattach ldconfig ldconfig.real logsave losetup mke2fs mkfs mkfs.bfs
mkfs.cramfs mkfs.ext2 mkfs.ext3 mkfs.ext4 mkfs.minix mkhomedir_helper mklost+found mkswap
newusers nologin pam-auth-update pam_extrausers_chkpwd pam_extrausers_update pam_getenv
pam_timestamp_check pivot_root policy-rc.d pwck pwconv pwunconv readprofile remove-shell
resize2fs rmt rmt-tar rtcwake runuser service shadowconfig start-stop-daemon sulogin
swaplabel swapoff swapon switch_root sysctl tarcat tune2fs unix_chkpwd unix_update update-
passwd update-rc.d update-shells useradd userdel usermod vigr vipw wipefs zic zramctl
""")

BIN_UBUNTU_24 = _names("""
[ addpart apt apt-cache apt-cdrom apt-config apt-get apt-key apt-mark arch awk b2sum base32
base64 basename basenc bash bashbug captoinfo cat chage chattr chcon chfn chgrp chmod choom
chown chrt chsh cksum clear clear_console cmp comm cp csplit cut dash date dd deb-systemd-
helper deb-systemd-invoke debconf debconf-apt-progress debconf-communicate debconf-copydb
debconf-escape debconf-set-selections debconf-show delpart df diff diff3 dir dircolors
dirname dmesg dnsdomainname domainname dpkg dpkg-deb dpkg-divert dpkg-maintscript-helper
dpkg-query dpkg-realpath dpkg-split dpkg-statoverride dpkg-trigger du echo egrep env expand
expiry expr factor faillog fallocate false fgrep find findmnt flock fmt fold free getconf
getent getopt gpasswd gpgv grep groups gunzip gzexe gzip hardlink head hostid hostname i386
iconv id infocmp infotocap install ionice ipcmk ipcrm ipcs ischroot join kill last lastb
lastlog ld.so ldd link linux32 linux64 ln locale locale-check localedef logger login logname
ls lsattr lsblk lscpu lsipc lslocks lslogins lsmem lsns man mawk mcookie md5sum
md5sum.textutils mesg mkdir mkfifo mknod mktemp more mount mountpoint mv namei nawk newgrp
nice nisdomainname nl nohup nproc nsenter numfmt od pager partx passwd paste pathchk perl
perl5.38.2 pgrep pidof pidwait pinky pkill pldd pmap pr printenv printf prlimit ps ptx pwd
pwdx rbash readlink realpath rename.ul renice reset resizepart rev rgrep rm rmdir run-parts
runcon savelog script scriptlive scriptreplay sdiff sed select-editor sensible-browser
sensible-editor sensible-pager sensible-terminal seq setarch setpriv setsid setterm sg sh
sha1sum sha224sum sha256sum sha384sum sha512sum shred shuf skill slabtop sleep snice sort
split stat stdbuf stty su sum sync tabs tac tail tar taskset tee tempfile test tic timeout
tload toe top touch tput tr true truncate tset tsort tty tzselect uclampset umount uname
uncompress unexpand uniq unlink unminimize unshare update-alternatives uptime users utmpdump
vdir vmstat w wall watch wc wdctl whereis which which.debianutils who whoami x86_64 xargs
yes ypdomainname zcat zcmp zdiff zdump zegrep zfgrep zforce zgrep zless zmore znew
""")
SBIN_UBUNTU_24 = _names("""
add-shell agetty badblocks blkdiscard blkid blkzone blockdev chcpu chgpasswd chmem chpasswd
chroot cpgr cppw ctrlaltdel debugfs dpkg-preconfigure dpkg-reconfigure dumpe2fs e2freefrag
e2fsck e2image e2label e2mmpstatus e2scrub e2scrub_all e2undo e4crypt e4defrag faillock
filefrag findfs fsck fsck.cramfs fsck.ext2 fsck.ext3 fsck.ext4 fsck.minix fsfreeze fstab-
decode fstrim getty groupadd groupdel groupmems groupmod grpck grpconv grpunconv iconvconfig
initctl installkernel invoke-rc.d isosize killall5 ldattach ldconfig ldconfig.real logsave
losetup mke2fs mkfs mkfs.bfs mkfs.cramfs mkfs.ext2 mkfs.ext3 mkfs.ext4 mkfs.minix
mkhomedir_helper mklost+found mkswap newusers nologin pam-auth-update pam_extrausers_chkpwd
pam_extrausers_update pam_getenv pam_namespace_helper pam_timestamp_check pivot_root policy-
rc.d pwck pwconv pwhistory_helper pwunconv readprofile remove-shell resize2fs rmt rmt-tar
rtcwake runuser service shadowconfig start-stop-daemon sulogin swaplabel swapoff swapon
switch_root sysctl tarcat tune2fs unix_chkpwd unix_update update-passwd update-rc.d update-
shells useradd userdel usermod vigr vipw wipefs zic zramctl
""")

BIN_DEBIAN = _names("""
[ addpart apt apt-cache apt-cdrom apt-config apt-get apt-key apt-mark arch awk b2sum base32
base64 basename basenc bash bashbug captoinfo cat chage chattr chcon chfn chgrp chmod choom
chown chrt chsh cksum clear clear_console cmp comm cp csplit cut dash date dd deb-systemd-
helper deb-systemd-invoke debconf debconf-apt-progress debconf-communicate debconf-copydb
debconf-escape debconf-set-selections debconf-show delpart df diff diff3 dir dircolors
dirname dmesg dnsdomainname domainname dpkg dpkg-deb dpkg-divert dpkg-maintscript-helper
dpkg-query dpkg-realpath dpkg-split dpkg-statoverride dpkg-trigger du echo egrep env expand
expiry expr factor faillog fallocate false fgrep fincore find findmnt flock fmt fold getconf
getent getopt gpasswd gpgv grep groups gunzip gzexe gzip hardlink head hostid hostname iconv
id infocmp infotocap install ionice ipcmk ipcrm ipcs ischroot join last lastb lastlog ld.so
ldd link linux32 linux64 ln locale localedef logger login logname ls lsattr lsblk lscpu lsfd
lsipc lsirq lslocks lslogins lsmem lsns mawk mcookie md5sum md5sum.textutils mesg mkdir
mkfifo mknod mktemp more mount mountpoint mv namei nawk newgrp nice nisdomainname nl nohup
nproc nsenter numfmt od pager partx passwd paste pathchk perl perl5.36.0 pidof pinky pldd pr
printenv printf prlimit ptx pwd rbash readlink realpath rename.ul renice reset resizepart
rev rgrep rm rmdir run-parts runcon savelog script scriptlive scriptreplay sdiff sed seq
setarch setpriv setsid setterm sg sh sha1sum sha224sum sha256sum sha384sum sha512sum shred
shuf sleep sort split stat stdbuf stty su sum sync tabs tac tail tar taskset tee tempfile
test tic timeout toe touch tput tr true truncate tset tsort tty tzselect uclampset umount
uname uncompress unexpand uniq unlink unshare update-alternatives users utmpdump vdir wall
wc wdctl whereis which which.debianutils who whoami xargs yes ypdomainname zcat zcmp zdiff
zdump zegrep zfgrep zforce zgrep zless zmore znew
""")
SBIN_DEBIAN = _names("""
add-shell addgroup adduser agetty badblocks blkdiscard blkid blkzone blockdev chcpu
chgpasswd chmem chpasswd chroot cpgr cppw ctrlaltdel debugfs delgroup deluser dpkg-fsys-
usrunmess dpkg-preconfigure dpkg-reconfigure dumpe2fs e2freefrag e2fsck e2image e2label
e2mmpstatus e2scrub e2scrub_all e2undo e4crypt e4defrag faillock filefrag findfs fsck
fsck.cramfs fsck.ext2 fsck.ext3 fsck.ext4 fsck.minix fsfreeze fstab-decode fstrim getty
groupadd groupdel groupmems groupmod grpck grpconv grpunconv hwclock iconvconfig
installkernel invoke-rc.d isosize killall5 ldattach ldconfig logsave losetup mke2fs mkfs
mkfs.bfs mkfs.cramfs mkfs.ext2 mkfs.ext3 mkfs.ext4 mkfs.minix mkhomedir_helper mklost+found
mkswap newusers nologin pam-auth-update pam_getenv pam_namespace_helper pam_timestamp_check
pivot_root policy-rc.d pwck pwconv pwhistory_helper pwunconv readprofile remove-shell
resize2fs rmt rmt-tar rtcwake runuser service shadowconfig start-stop-daemon sulogin
swaplabel swapoff swapon switch_root tarcat tune2fs unix_chkpwd unix_update update-passwd
update-rc.d update-shells useradd userdel usermod vigr vipw wipefs zic zramctl
""")

BIN_RHEL = _names("""
[ addr2line alias ar arch arping as attr awk b2sum base32 base64 basename basenc bash
bashbug bashbug-64 bg c++filt ca-legacy cal cat catchsegv cd chage chcon chgrp chmem chmod
choom chown chrt cksum clockdiff col colcrt colrm column comm command consolehelper
coreutils cp csplit curl cut cyrusbdb2current date dd debuginfod-find df dir dircolors
dirmngr dirmngr-client dirname dmesg dnf dnf-3 dnf4 dnsdomainname domainname du dwp echo
egrep eject elfedit env evmctl ex expand expr factor fallocate false fc fg fgrep fincore
find findmnt fips-finish-install fips-mode-setup flock fmt fold g13 gapplication gawk gdbus
gencat getconf getent getfattr getopt getopts gio gio-querymodules-64 glib-compile-schemas
gpasswd gpg gpg-agent gpg-card gpg-connect-agent gpg-error gpg-wks-client gpg-wks-server
gpg2 gpgconf gpgme-json gpgparsemail gpgsplit gpgtar gpgv gpgv2 gprof grep groups gsettings
gtar gunzip gzexe gzip hardlink hash head hexdump hostid hostname iconv id ima-add-sigs ima-
setup install ionice ipcmk ipcrm ipcs irqtop isosize jobs join keyctl kill last lastb
lastlog lchfn lchsh ld ld.bfd ld.gold ld.so ldd less lessecho lesskey lesspipe.sh link
linux32 linux64 ln locale localedef logger login logname look ls lsblk lscpu lsipc lsirq
lslocks lslogins lsmem lsns make-dummy-cert mcookie md5sum mesg mkdir mkfifo mknod mktemp
modulemd-validator more mount mountpoint mv namei newgidmap newgrp newuidmap nice
nisdomainname nl nm nohup nproc nsenter numfmt objcopy objdump od openssl p11-kit passwd
paste pathchk ping pinky pldd pr printenv printf prlimit ptx pwd pwmake pwscore pydoc pydoc3
pydoc3.9 python3 python3.9 ranlib read readelf readlink realpath rename renew-dummy-cert
renice rev rm rmdir rpm rpm2archive rpm2cpio rpmdb rpmkeys rpmquery rpmverify runcon rvi
rview script scriptlive scriptreplay sed seq setarch setfattr setpriv setsid setterm sg sh
sha1sum sha224sum sha256sum sha384sum sha512sum shred shuf size sleep sort sotruss split
sprof stat stdbuf strings strip stty su sum sync tac tail tar taskset tee test timeout touch
tr tracepath true truncate trust tsort tty type tzselect ul ulimit umask umount unalias
uname uname26 unexpand uniq unlink unshare update-ca-trust update-crypto-policies users
utmpdump uuidgen uuidparse vdir vi view wait wall watchgnupg wc wdctl whereis who whoami
write xargs xmlcatalog xmllint xmlwf yes ypdomainname yum zcat zcmp zdiff zdump zegrep
zfgrep zforce zgrep zless zmore znew
""")
SBIN_RHEL = _names("""
addgnupghome addpart adduser agetty alternatives applygnupgdefaults arping blkdiscard blkid
blkzone blockdev capsh cfdisk chcpu chgpasswd chpasswd chroot clock cracklib-check cracklib-
format cracklib-packer cracklib-unpacker create-cracklib-dict ctrlaltdel delpart faillock
fdformat fdisk findfs fsck fsck.cramfs fsck.minix fsfreeze fstrim g13-syshelp getcap
getpcaps groupadd groupdel groupmems groupmod grpck grpconv grpunconv hwclock iconvconfig
ifenslave key.dns_resolver lchage ldattach ldconfig lgroupadd lgroupdel lgroupmod lid
lnewusers losetup lpasswd luseradd luserdel lusermod mkdict mkfs mkfs.cramfs mkfs.minix
mkhomedir_helper mkswap newusers nologin packer pam_console_apply pam_namespace_helper
pam_timestamp_check partx ping ping6 pivot_root pwck pwconv pwhistory_helper pwunconv rdisc
readprofile request-key resizepart rfkill rtcwake runuser sasldblistusers2 saslpasswd2
setcap sfdisk sulogin swaplabel swapoff swapon switch_root tracepath tracepath6 unix_chkpwd
unix_update update-alternatives useradd userdel userhelper usermod vigr vipw wipefs zic
zramctl
""")


# family -> (/usr/bin, /usr/sbin); Ubuntu before 24.04 uses the 22.04 lists.
LISTS = {"ubuntu-22": (BIN_UBUNTU_22, SBIN_UBUNTU_22),
         "ubuntu-24": (BIN_UBUNTU_24, SBIN_UBUNTU_24),
         "debian": (BIN_DEBIAN, SBIN_DEBIAN), "rhel": (BIN_RHEL, SBIN_RHEL)}
