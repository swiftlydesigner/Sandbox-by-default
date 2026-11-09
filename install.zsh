sudo apt install micro gcc make libseccomp-dev -y
sudo sed -i '/^GRUB_CMDLINE_LINUX_DEFAULT="/ s/"$/ systemd.unified_cgroup_hierarchy=1 cgroup_no_v1=all"/' /etc/default/grub
sudo update-grub
sudo reboot
