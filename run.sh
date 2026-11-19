#!/bin/bash

REBOOT=false

TEST=true

if dpkg -s libseccomp-dev >/dev/null 2>&1; then
	echo 'libseccomp-dev installed.'
else
	sudo apt install libseccomp-dev -y
	REBOOT=true
fi

if dpkg -s gcc >/dev/null 2>&1; then
	echo 'gcc installed.'
else
	sudo apt install gcc -y
	REBOOT=true
fi

if dpkg -s make > /dev/null 2>&1; then
	echo 'make installed.'
else
	sudo apt install make -y
	REBOOT=true
fi

if $(stat -fc %T /sys/fs/cgroup) != 'cgroup2fs'; then
	sudo sed -i '/^GRUB_CMDLINE_LINUX_DEFAULT="/ s/"$/ systemd.unified_cgroup_hierarchy=1 cgroup_no_v1=all"/' /etc/default/grub
    sudo update-grub
    sudo reboot
	REBOOT=true
fi

if REBOOT; then
	echo "System must reboot. Scheduled for 10 sec. CTRL-C TO ABORT REBOOT!!"
	sleep 10
	sudo reboot
	exit -1;
fi

make clean && make && ./sandbox 

if TEST; then
    gcc malicious/esc_fs.c -o escape_fs
    gcc malicious/networking.c -o mal_net
    gcc malicious/exhaust_cpu.c -o exh_cpu
    gcc malicious/exhaust_mem.c -o exh_mem
    gcc malicious/set_uid_root.c -o set_uid
    gcc malicious/snoop_mem.c -o snoop
fi
