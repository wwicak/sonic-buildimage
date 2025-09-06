#!/bin/bash
## This script is to automate loading of vendor specific docker images
## and installation of configuration files and vendor specific packages
## to debian file system.
##
## USAGE:
##   ./sonic_debian_extension.sh FILESYSTEM_ROOT PLATFORM_DIR
## PARAMETERS:
##   FILESYSTEM_ROOT
##          Path to debian file system root directory

FILESYSTEM_ROOT=$1
[ -n "$FILESYSTEM_ROOT" ] || {
    echo "Error: no or empty FILESYSTEM_ROOT argument"
    exit 1
}

PLATFORM_DIR=$2
[ -n "$PLATFORM_DIR" ] || {
    echo "Error: no or empty PLATFORM_DIR argument"
    exit 1
}

IMAGE_DISTRO=$3
[ -n "$IMAGE_DISTRO" ] || {
    echo "Error: no or empty IMAGE_DISTRO argument"
    exit 1
}

## Enable debug output for script
set -x -e

CONFIGURED_ARCH=$([ -f .arch ] && cat .arch || echo amd64)
CONFIGURED_PLATFORM=$([ -f .platform ] && cat .platform || echo generic)

. functions.sh
BUILD_SCRIPTS_DIR=files/build_scripts
BUILD_TEMPLATES=files/build_templates
IMAGE_CONFIGS=files/image_config
SCRIPTS_DIR=files/scripts
DOCKER_SCRIPTS_DIR=files/docker

DOCKER_CTL_DIR=/usr/lib/docker/
DOCKER_CTL_SCRIPT="$DOCKER_CTL_DIR/docker.sh"

# Define target fold macro
FILESYSTEM_ROOT_USR="$FILESYSTEM_ROOT/usr"
FILESYSTEM_ROOT_USR_LIB="$FILESYSTEM_ROOT/usr/lib/"
FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM="$FILESYSTEM_ROOT_USR_LIB/systemd/system"
FILESYSTEM_ROOT_USR_LIB_SYSTEMD_NETWORK="$FILESYSTEM_ROOT_USR_LIB/systemd/network"
FILESYSTEM_ROOT_USR_SHARE="$FILESYSTEM_ROOT_USR/share"
FILESYSTEM_ROOT_USR_SHARE_SONIC="$FILESYSTEM_ROOT_USR_SHARE/sonic"
FILESYSTEM_ROOT_USR_SHARE_SONIC_SCRIPTS="$FILESYSTEM_ROOT_USR_SHARE_SONIC/scripts"
FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES="$FILESYSTEM_ROOT_USR_SHARE_SONIC/templates"
FILESYSTEM_ROOT_USR_SHARE_SONIC_FIRMWARE="$FILESYSTEM_ROOT_USR_SHARE_SONIC/firmware"
FILESYSTEM_ROOT_ETC="$FILESYSTEM_ROOT/etc"
FILESYSTEM_ROOT_ETC_SONIC="$FILESYSTEM_ROOT_ETC/sonic"

GENERATED_SERVICE_FILE="$FILESYSTEM_ROOT/etc/sonic/generated_services.conf"

clean_sys() {
    sudo chroot $FILESYSTEM_ROOT umount /sys/fs/cgroup/*            \
                                        /sys/fs/cgroup              \
                                        /sys || true
}
trap_push clean_sys
sudo LANG=C chroot $FILESYSTEM_ROOT mount sysfs /sys -t sysfs

sudo bash -c "echo \"DOCKER_OPTS=\"--storage-driver=overlay2\"\" >> $FILESYSTEM_ROOT/etc/default/docker"
# Copy docker start script to be able to start docker in chroot
sudo mkdir -p "$FILESYSTEM_ROOT/$DOCKER_CTL_DIR"
sudo cp $DOCKER_SCRIPTS_DIR/docker "$FILESYSTEM_ROOT/$DOCKER_CTL_SCRIPT"
if [[ $MULTIARCH_QEMU_ENVIRON == y  || $CROSS_BUILD_ENVIRON == y ]]; then
    DOCKER_HOST="unix:///dockerfs/var/run/docker.sock"
    SONIC_NATIVE_DOCKERD_FOR_DOCKERFS_PID="cat `pwd`/dockerfs/var/run/docker.pid"
else
    sudo chroot $FILESYSTEM_ROOT $DOCKER_CTL_SCRIPT start
fi

install_pip_package() {
    pip_wheel=$1
    if [[ -z "$pip_wheel" ]]; then
        return
    fi
    sudo cp $pip_wheel $FILESYSTEM_ROOT/
    basename_pip_wheel=$(basename -a $@)
    sudo https_proxy=$https_proxy LANG=C chroot $FILESYSTEM_ROOT pip3 install $basename_pip_wheel
    ( cd $FILESYSTEM_ROOT; sudo rm -f $basename_pip_wheel )
}

install_deb_package() {
    deb_packages=$@
    if [[ -z "$deb_packages" ]]; then
        return
    fi
    sudo cp $deb_packages $FILESYSTEM_ROOT/
    basename_deb_packages=$(basename -a $@)
    sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT dpkg -i $basename_deb_packages || \
        sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-get -y install -f
    ( cd $FILESYSTEM_ROOT; sudo rm -f $basename_deb_packages )
}

install_deb_package_lazy() {
    deb_packages=$@
    if [[ -z "$deb_packages" ]]; then
        return
    fi
    sudo cp $deb_packages $FILESYSTEM_ROOT/
    basename_deb_packages=$(basename -a $@)
    sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT dpkg -i $basename_deb_packages || \
        sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-get -y install -f --download-only
    ( cd $FILESYSTEM_ROOT; sudo rm -f $basename_deb_packages )
}

# Update apt's snapshot of its repos
sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-get update

# Install efitools to support secure upgrade
sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-get -y install efitools
sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-get -y install mokutil

# Apply environtment configuration files
sudo cp $IMAGE_CONFIGS/environment/environment $FILESYSTEM_ROOT/etc/
sudo cp $IMAGE_CONFIGS/environment/motd $FILESYSTEM_ROOT/etc/
sudo cp $IMAGE_CONFIGS/environment/logout_message $FILESYSTEM_ROOT/etc/

# Create all needed directories
sudo mkdir -p $FILESYSTEM_ROOT/etc/sonic/
sudo mkdir -p $FILESYSTEM_ROOT/etc/modprobe.d/
sudo mkdir -p $FILESYSTEM_ROOT/var/cache/sonic/
sudo mkdir -p $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/
sudo mkdir -p $FILESYSTEM_ROOT_USR_SHARE_SONIC_FIRMWARE/
# This is needed for Stretch and might not be needed for Buster where Linux create this directory by default.
# Keeping it generic. It should not harm anyways.
sudo mkdir -p $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM

# Install sonic-nettools
install_deb_package $debs_path/sonic-nettools_*.deb
sudo setcap 'cap_net_raw=+ep' $FILESYSTEM_ROOT/usr/bin/wol

# This is needed for moving monit logs, state and logrotate status to tmpfs
sudo bash -c "echo \"d	/dev/shm/monit/ 0755 root root\" > $FILESYSTEM_ROOT/etc/tmpfiles.d/tmpfs-monit.conf"
sudo bash -c "echo \"d	/dev/shm/logrotate/ 0755 root root\" > $FILESYSTEM_ROOT/etc/tmpfiles.d/tmpfs-logrotate.conf"


# Install a patched version of ifupdown2  (and its dependencies via 'apt-get -y install -f')
install_deb_package $debs_path/ifupdown2_*.deb

# Install dependencies for SONiC config engine
sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-get -y install \
    python3-dev

# Install j2cli for handling jinja template
sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-get -y install j2cli

# Install Python client for Redis
sudo https_proxy=$https_proxy LANG=C chroot $FILESYSTEM_ROOT pip3 install "redis==3.5.3"

# Install redis-dump-load Python 3 package
# Note: the scripts will be overwritten by corresponding Python 2 package

install_pip_package target/python-wheels/bookworm/redis_dump_load-1.1-py3-none-any.whl

# Install Python module for psutil
sudo https_proxy=$https_proxy LANG=C chroot $FILESYSTEM_ROOT pip3 install psutil

# Install Python module for blkinfo
sudo https_proxy=$https_proxy LANG=C chroot $FILESYSTEM_ROOT pip3 install blkinfo

# Install Python module for ipaddr
sudo https_proxy=$https_proxy LANG=C chroot $FILESYSTEM_ROOT pip3 install ipaddr

# Install Python module for grpcio and grpcio-toole
if [[ $CONFIGURED_ARCH == amd64 || $CONFIGURED_ARCH == arm64 ]]; then
    sudo https_proxy=$https_proxy LANG=C chroot $FILESYSTEM_ROOT pip3 install "grpcio==1.58.0"
    sudo https_proxy=$https_proxy LANG=C chroot $FILESYSTEM_ROOT pip3 install "grpcio-tools==1.58.0"
fi

# Install Python module for smbus2
sudo https_proxy=$https_proxy LANG=C chroot $FILESYSTEM_ROOT pip3 install smbus2

# Install Python module for telnetlib3
sudo https_proxy=$https_proxy LANG=C chroot $FILESYSTEM_ROOT pip3 install telnetlib3

# Install sonic-py-common Python 3 package
install_pip_package target/python-wheels/bookworm/sonic_py_common-1.0-py3-none-any.whl

# Install dependency pkgs for SONiC config engine Python 2 package
if [[ $CONFIGURED_ARCH == armhf || $CONFIGURED_ARCH == arm64 ]]; then
    sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-get -y install libxslt-dev libz-dev
fi

# Install sonic-yang-models Python 3 package, install dependencies
install_deb_package $debs_path/libyang_*.deb $debs_path/libyang-cpp_*.deb $debs_path/python3-yang_*.deb
install_pip_package target/python-wheels/bookworm/sonic_yang_models-1.0-py3-none-any.whl

# Install sonic-yang-mgmt Python3 package
install_pip_package target/python-wheels/bookworm/sonic_yang_mgmt-1.0-py3-none-any.whl

# For sonic-config-engine Python 3 package
# Install pyangbind here, outside sonic-config-engine dependencies, as pyangbind causes enum34 to be installed.
# Then immediately uninstall enum34, as enum34 should not be installed for Python >= 3.4, as it causes a
# conflict with the new 'enum' module in the standard library
# https://github.com/robshakir/pyangbind/issues/232
sudo https_proxy=$https_proxy LANG=C chroot $FILESYSTEM_ROOT pip3 install pyangbind==0.8.2
sudo https_proxy=$https_proxy LANG=C chroot $FILESYSTEM_ROOT pip3 uninstall -y enum34

# Install SONiC config engine Python 3 package
install_pip_package target/python-wheels/bookworm/sonic_config_engine-1.0-py3-none-any.whl


# Install sonic-platform-common Python 3 package
install_pip_package target/python-wheels/bookworm/sonic_platform_common-1.0-py3-none-any.whl


# Install pddf-platform-api-base Python 3 package
install_pip_package "target/python-wheels/bookworm/sonic_platform_pddf_common-1.0-py3-none-any.whl"





# Install system-health Python 3 package
install_pip_package "target/python-wheels/bookworm/system_health-1.0-py3-none-any.whl"

# Install m2crypto, cryptography, cffi, and pynacl packages, used by sonic-utilities
sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-get -y install python3-m2crypto python3-cryptography python3-cffi python3-nacl

# install libffi-dev to match utilities' dependency.
sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-get -y install libffi-dev

# Install SONiC Utilities Python package
install_pip_package target/python-wheels/bookworm/sonic_utilities-1.2-py3-none-any.whl

# Install sonic-utilities data files (and any dependencies via 'apt-get -y install -f')
install_deb_package $debs_path/sonic-utilities-data_*.deb

# Install customized bash version to patch bash plugin support.
install_deb_package $debs_path/bash_*.deb

# sonic-utilities-data installs bash-completion as a dependency. However, it is disabled by default
# in bash.bashrc, so we copy a version of the file with it enabled here.
sudo cp -f $IMAGE_CONFIGS/bash/bash.bashrc $FILESYSTEM_ROOT/etc/
sudo cp -f $IMAGE_CONFIGS/bash/bash.bash_logout $FILESYSTEM_ROOT/etc/

# Install readline's initialization file
sudo cp -f $IMAGE_CONFIGS/readline/inputrc $FILESYSTEM_ROOT/etc/

# Install prerequisites needed for installing the dependent Python packages of sonic-host-services
# These packages can be uninstalled after installation
sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-get -y install libcairo2-dev libdbus-1-dev libgirepository1.0-dev libsystemd-dev pkg-config python3-dbus

# Mark runtime dependencies as manually installed to avoid them being auto-removed while uninstalling build dependencies
sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-mark manual gir1.2-glib-2.0 libdbus-1-3 libgirepository-1.0-1 libsystemd0 python3-dbus

# Install systemd-python for SONiC host services
sudo https_proxy=$https_proxy LANG=C chroot $FILESYSTEM_ROOT pip3 install systemd-python

# Install pygobject from apt repos. The version in Debian is
# a bit older than what is in pip, but it should be fine.
sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-get -y install python3-gi

# Install SONiC host services package
install_pip_package target/python-wheels/bookworm/sonic_host_services-1.0-py3-none-any.whl

# Install SONiC host services data files (and any dependencies via 'apt-get -y install -f')
install_deb_package $debs_path/sonic-host-services-data_*.deb





# Install SONiC Device Data  (and its dependencies via 'apt-get -y install -f')
install_deb_package $debs_path/sonic-device-data_*.deb

# package for supporting password hardening
sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-get -y install libpam-pwquality

# Install pam-ldap, nss-ldap, ldap-utils
sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-get -y install      \
    libnss-ldapd \
    libpam-ldapd \
    ldap-utils

# add networking.service dependancy to nslcd
sudo LANG=C chroot $FILESYSTEM_ROOT sed -i '/# Required-Start:/ s/$/ networking.service/' /etc/init.d/nslcd

# nslcd disable default
sudo LANG=C chroot $FILESYSTEM_ROOT systemctl stop nslcd.service
sudo LANG=C chroot $FILESYSTEM_ROOT systemctl mask nslcd.service

# Install pam-tacplus and nss-tacplus
install_deb_package $debs_path/libtac2_*.deb
install_deb_package $debs_path/libpam-tacplus_*.deb
install_deb_package $debs_path/libnss-tacplus_*.deb
# Install bash-tacplus
install_deb_package $debs_path/bash-tacplus_*.deb
# Install audisp-tacplus
install_deb_package $debs_path/audisp-tacplus_*.deb
# Disable tacplus and LDAP by default
## NOTE: this syntax of pam-auth-update is meant to be used when the package gets removed, not for specifying
## some local configuration of a PAM module. Currently, there's no clean way of noninteractively specifying
## whether some PAM module needs to be enabled or disabled on a system (there are hacky ways, though).
##
## If there is some PAM module that's installed/removed after this point, then this setting will end up having
## no impact, and there may be errors/test failures related to authentication.
sudo LANG=C chroot $FILESYSTEM_ROOT pam-auth-update --remove tacplus ldap
sudo sed -i -e '/^passwd/s/ tacplus//' $FILESYSTEM_ROOT/etc/nsswitch.conf

# Install pam-radius-auth and nss-radius
install_deb_package $debs_path/libpam-radius-auth_*.deb
install_deb_package $debs_path/libnss-radius_*.deb
# Disable radius by default
# radius does not have any profiles
#sudo LANG=C chroot $FILESYSTEM_ROOT pam-auth-update --remove radius tacplus
sudo sed -i -e '/^passwd/s/ radius//' $FILESYSTEM_ROOT/etc/nsswitch.conf

# Install a custom version of kdump-tools  (and its dependencies via 'apt-get -y install -f')
if [ "$TARGET_BOOTLOADER" != uboot ]; then
    install_deb_package $debs_path/kdump-tools_*.deb
    cat $IMAGE_CONFIGS/kdump/kdump-tools | sudo tee -a $FILESYSTEM_ROOT/etc/default/kdump-tools > /dev/null

for kernel_release in $(ls $FILESYSTEM_ROOT/lib/modules/); do
	sudo LANG=C chroot $FILESYSTEM_ROOT /etc/kernel/postinst.d/kdump-tools $kernel_release > /dev/null 2>&1
	sudo LANG=C chroot $FILESYSTEM_ROOT kdump-config symlinks $kernel_release
done
fi

# Install python-swss-common package and all its dependent packages
install_deb_package target/debs/bookworm/libnl-3-200_3.7.0-0.2+b1sonic1_amd64.deb
install_deb_package target/debs/bookworm/libnl-genl-3-200_3.7.0-0.2+b1sonic1_amd64.deb
install_deb_package target/debs/bookworm/libnl-route-3-200_3.7.0-0.2+b1sonic1_amd64.deb
install_deb_package target/debs/bookworm/libnl-nf-3-200_3.7.0-0.2+b1sonic1_amd64.deb
install_deb_package target/debs/bookworm/libnl-cli-3-200_3.7.0-0.2+b1sonic1_amd64.deb
install_deb_package target/debs/bookworm/libyang_1.0.73_amd64.deb
install_deb_package target/debs/bookworm/libswsscommon_1.0.0_amd64.deb
install_deb_package 
install_deb_package target/debs/bookworm/python3-swsscommon_1.0.0_amd64.deb



# Install sonic-db-cli
install_deb_package $debs_path/sonic-db-cli_*.deb




# Install custom-built monit package and SONiC configuration files
install_deb_package $debs_path/monit_*.deb
sudo cp $IMAGE_CONFIGS/monit/monitrc $FILESYSTEM_ROOT/etc/monit/
sudo chmod 600 $FILESYSTEM_ROOT/etc/monit/monitrc
sudo cp $IMAGE_CONFIGS/monit/conf.d/* $FILESYSTEM_ROOT/etc/monit/conf.d/
sudo chmod 600 $FILESYSTEM_ROOT/etc/monit/conf.d/*
sudo cp $IMAGE_CONFIGS/monit/container_checker $FILESYSTEM_ROOT/usr/bin/
sudo chmod 755 $FILESYSTEM_ROOT/usr/bin/container_checker
sudo cp $IMAGE_CONFIGS/monit/memory_checker $FILESYSTEM_ROOT/usr/bin/
sudo chmod 755 $FILESYSTEM_ROOT/usr/bin/memory_checker
sudo cp $IMAGE_CONFIGS/monit/restart_service $FILESYSTEM_ROOT/usr/bin/
sudo chmod 755 $FILESYSTEM_ROOT/usr/bin/restart_service
sudo cp $IMAGE_CONFIGS/monit/arp_update_checker $FILESYSTEM_ROOT/usr/bin/
sudo chmod 755 $FILESYSTEM_ROOT/usr/bin/arp_update_checker
sudo cp $IMAGE_CONFIGS/monit/control_plane_drop_check $FILESYSTEM_ROOT/usr/bin/
sudo chmod 755 $FILESYSTEM_ROOT/usr/bin/control_plane_drop_check
sudo cp $IMAGE_CONFIGS/monit/mgmt_oper_status.py $FILESYSTEM_ROOT/usr/bin/
sudo chmod 755 $FILESYSTEM_ROOT/usr/bin/mgmt_oper_status.py

# Installed smartmontools version should match installed smartmontools in docker-platform-monitor Dockerfile
# TODO: are mismatching versions fine for bookworm?
sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-get -y install -t bookworm-backports smartmontools
sudo cp $IMAGE_CONFIGS/smartmontools/smartmontools $FILESYSTEM_ROOT/etc/default/smartmontools

# Install custom-built openssh sshd
install_deb_package $debs_path/openssh-server_${OPENSSH_VERSION_FULL}_*.deb $debs_path/openssh-client_${OPENSSH_VERSION_FULL}_*.deb $debs_path/openssh-sftp-server_${OPENSSH_VERSION_FULL}_*.deb



# Copy crontabs
sudo cp -f $IMAGE_CONFIGS/cron.d/* $FILESYSTEM_ROOT/etc/cron.d/

# Copy NTP configuration files and templates
sudo cp $IMAGE_CONFIGS/chrony/chrony-config.sh $FILESYSTEM_ROOT/usr/bin/
sudo cp $IMAGE_CONFIGS/chrony/chrony.conf.j2 $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/
sudo cp $IMAGE_CONFIGS/chrony/chrony.keys.j2 $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/
sudo cp $IMAGE_CONFIGS/chrony/chronyd-starter.sh $FILESYSTEM_ROOT/usr/local/sbin/
sudo cp $IMAGE_CONFIGS/chrony/check_ntp_status.sh $FILESYSTEM_ROOT/usr/local/bin/
sudo mkdir $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM/chrony.service.d
# Don't start chrony with multi-user.target, add our override, and start it with sonic.target
sudo LANG=C chroot $FILESYSTEM_ROOT systemctl disable chrony.service
sudo cp $IMAGE_CONFIGS/chrony/override.conf $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM/chrony.service.d/
sudo LANG=C chroot $FILESYSTEM_ROOT systemctl enable chrony.service

# Copy DNS templates
sudo cp $BUILD_TEMPLATES/dns.j2 $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/

# Copy cli-sessions config files
sudo cp $IMAGE_CONFIGS/cli_sessions/tmout-env.sh.j2 $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/
sudo cp $IMAGE_CONFIGS/cli_sessions/sysrq-sysctl.conf.j2 $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/
sudo cp $IMAGE_CONFIGS/cli_sessions/serial-config.sh $FILESYSTEM_ROOT/usr/bin/
sudo cp $IMAGE_CONFIGS/cli_sessions/serial-config.service $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM
echo "serial-config.service" | sudo tee -a $GENERATED_SERVICE_FILE

# Copy warmboot-finalizer files
sudo LANG=C cp $IMAGE_CONFIGS/warmboot-finalizer/finalize-warmboot.sh $FILESYSTEM_ROOT/usr/local/bin/finalize-warmboot.sh
sudo LANG=C cp $IMAGE_CONFIGS/warmboot-finalizer/warmboot-finalizer.service $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM
echo "warmboot-finalizer.service" | sudo tee -a $GENERATED_SERVICE_FILE

# Copy watchdog-control files
sudo LANG=C cp $IMAGE_CONFIGS/watchdog-control/watchdog-control.sh $FILESYSTEM_ROOT/usr/local/bin/watchdog-control.sh
sudo LANG=C cp $IMAGE_CONFIGS/watchdog-control/watchdog-control.service $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM
echo "watchdog-control.service" | sudo tee -a $GENERATED_SERVICE_FILE

# Copy rsyslog configuration files and templates
sudo cp $IMAGE_CONFIGS/rsyslog/rsyslog-config.service $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM
sudo cp $IMAGE_CONFIGS/rsyslog/rsyslog-config.sh $FILESYSTEM_ROOT/usr/bin/
sudo cp $IMAGE_CONFIGS/rsyslog/rsyslog.conf.j2 $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/
sudo cp $IMAGE_CONFIGS/rsyslog/rsyslog-container.conf.j2 $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/
j2 $IMAGE_CONFIGS/rsyslog/rsyslog.d/00-sonic.conf.j2 | sudo tee $FILESYSTEM_ROOT/etc/rsyslog.d/00-sonic.conf
sudo cp $IMAGE_CONFIGS/rsyslog/rsyslog.d/*.conf $FILESYSTEM_ROOT/etc/rsyslog.d/
echo "rsyslog-config.service" | sudo tee -a $GENERATED_SERVICE_FILE

# Copy containercfgd configuration files
sudo cp $IMAGE_CONFIGS/containercfgd/containercfgd.conf $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/

# Copy syslog override files
sudo mkdir -p $FILESYSTEM_ROOT/etc/systemd/system/syslog.socket.d
sudo cp $IMAGE_CONFIGS/syslog/override.conf $FILESYSTEM_ROOT/etc/systemd/system/syslog.socket.d/override.conf
sudo cp $IMAGE_CONFIGS/syslog/host_umount.sh $FILESYSTEM_ROOT/usr/bin/

# Copy system-health files
sudo LANG=C cp $IMAGE_CONFIGS/system-health/system-health.service $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM
echo "system-health.service" | sudo tee -a $GENERATED_SERVICE_FILE

# Copy logrotate.d configuration files
sudo cp -f $IMAGE_CONFIGS/logrotate/logrotate.d/* $FILESYSTEM_ROOT/etc/logrotate.d/
sudo cp $IMAGE_CONFIGS/logrotate/rsyslog.j2 $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/
sudo cp $IMAGE_CONFIGS/logrotate/on_demand_archived_log_clean_up.j2 $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/
sudo cp $IMAGE_CONFIGS/logrotate/logrotate-config.service $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM
sudo cp $IMAGE_CONFIGS/logrotate/logrotate-config.sh $FILESYSTEM_ROOT/usr/bin/
sudo mkdir -p $FILESYSTEM_ROOT/etc/systemd/system/logrotate.timer.d
sudo cp $IMAGE_CONFIGS/logrotate/timerOverride.conf $FILESYSTEM_ROOT/etc/systemd/system/logrotate.timer.d/
echo "logrotate-config.service" | sudo tee -a $GENERATED_SERVICE_FILE

# Copy systemd-journald configuration files
sudo cp -f $IMAGE_CONFIGS/systemd/journald.conf $FILESYSTEM_ROOT/etc/systemd/

# Copy interfaces configuration files and templates
sudo cp $IMAGE_CONFIGS/interfaces/interfaces-config.service $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM
sudo cp $IMAGE_CONFIGS/interfaces/interfaces-config.sh $FILESYSTEM_ROOT/usr/bin/
sudo cp $IMAGE_CONFIGS/interfaces/*.j2 $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/
echo "interfaces-config.service" | sudo tee -a $GENERATED_SERVICE_FILE

# Copy CoPP configuration files and templates
sudo cp $IMAGE_CONFIGS/copp/copp-config.service $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM
sudo cp $IMAGE_CONFIGS/copp/copp-config.sh $FILESYSTEM_ROOT/usr/bin/
sudo cp $IMAGE_CONFIGS/copp/copp_cfg.j2 $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/
echo "copp-config.service" | sudo tee -a $GENERATED_SERVICE_FILE

sudo cp $IMAGE_CONFIGS/dhcp_dos_logger/dhcp_dos_logger.service $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM
sudo cp $IMAGE_CONFIGS/dhcp_dos_logger/dhcp_dos_logger.py $FILESYSTEM_ROOT/usr/bin/
sudo chmod 755 $FILESYSTEM_ROOT/usr/bin/dhcp_dos_logger.py
echo "dhcp_dos_logger.service" | sudo tee -a $GENERATED_SERVICE_FILE

# Copy dhcp client configuration template and create an initial configuration
sudo cp files/dhcp/dhclient.conf.j2 $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/
j2 files/dhcp/dhclient.conf.j2 | sudo tee $FILESYSTEM_ROOT/etc/dhcp/dhclient.conf
sudo cp files/dhcp/ifupdown2_policy.json $FILESYSTEM_ROOT/etc/network/ifupdown2/policy.d
sudo cp files/dhcp/90-dhcp6-systcl.conf.j2 $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/

# Copy DNS configuration files and templates
sudo cp $IMAGE_CONFIGS/resolv-config/resolv-config.service $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM
sudo cp $IMAGE_CONFIGS/resolv-config/resolv-config.sh $FILESYSTEM_ROOT/usr/bin/
sudo cp $IMAGE_CONFIGS/resolv-config/resolv.conf.j2 $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/
echo "resolv-config.service" | sudo tee -a $GENERATED_SERVICE_FILE
sudo LANG=C chroot $FILESYSTEM_ROOT systemctl disable resolvconf.service
sudo mkdir -p $FILESYSTEM_ROOT/etc/resolvconf/update-libc.d/
sudo cp $IMAGE_CONFIGS/resolv-config/update-containers $FILESYSTEM_ROOT/etc/resolvconf/update-libc.d/

# Copy initial interfaces configuration file, will be overwritten on first boot
sudo cp $IMAGE_CONFIGS/interfaces/init_interfaces $FILESYSTEM_ROOT/etc/network/interfaces
sudo mkdir -p $FILESYSTEM_ROOT/etc/network/interfaces.d

# Systemd network udev rules
sudo cp $IMAGE_CONFIGS/systemd/network/* $FILESYSTEM_ROOT_ETC/systemd/network/
sudo mkdir -p $FILESYSTEM_ROOT_ETC/udev/rules.d
sudo cp $IMAGE_CONFIGS/udev/rules.d/* $FILESYSTEM_ROOT_ETC/udev/rules.d/

# copy core file uploader files
sudo cp $IMAGE_CONFIGS/corefile_uploader/core_uploader.service $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM
sudo LANG=C chroot $FILESYSTEM_ROOT systemctl disable core_uploader.service
sudo cp $IMAGE_CONFIGS/corefile_uploader/core_uploader.py $FILESYSTEM_ROOT/usr/bin/
sudo cp $IMAGE_CONFIGS/corefile_uploader/core_analyzer.rc.json $FILESYSTEM_ROOT_ETC_SONIC/
sudo chmod og-rw $FILESYSTEM_ROOT_ETC_SONIC/core_analyzer.rc.json

if [[ $CONFIGURED_ARCH == amd64 ]]; then
    # Install rasdaemon package
    # NOTE: Can be installed from debian directly when we move to trixie
    install_deb_package $debs_path/rasdaemon_*.deb

    # Rasdaemon service configuration. Use timer to start rasdaemon with a delay for better fast/warm boot performance
    sudo cp $IMAGE_CONFIGS/rasdaemon/rasdaemon.timer $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM
    sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT systemctl disable rasdaemon.service
    sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT systemctl enable rasdaemon.timer
fi

sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-get -y install libffi-dev libssl-dev



sudo https_proxy=$https_proxy LANG=C chroot $FILESYSTEM_ROOT pip3 install azure-storage==0.36.0
sudo https_proxy=$https_proxy LANG=C chroot $FILESYSTEM_ROOT pip3 install watchdog==0.10.3

# sonic-ctrmgrd-rs is required by container script
install_deb_package $debs_path/sonic-ctrmgrd-rs_*.deb


# container script for docker commands, which is required as
# all docker commands are replaced with container commands.
# So just copy that file only.
#
sudo cp ${files_path}/container $FILESYSTEM_ROOT/usr/local/bin/


# Copy the buffer configuration template
sudo cp $BUILD_TEMPLATES/buffers_config.j2 $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/

# Copy the qos configuration template
sudo cp $BUILD_TEMPLATES/qos_config.j2 $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/

# Copy the templates for dynamically buffer calculation

if [ -f platform/vs/asic_table.j2 ]
then
    sudo cp platform/vs/asic_table.j2 $FILESYSTEM_ROOT/usr/share/sonic/templates/asic_table.j2
fi

if [ -f platform/vs/peripheral_table.j2 ]
then
    sudo cp platform/vs/peripheral_table.j2 $FILESYSTEM_ROOT/usr/share/sonic/templates/peripheral_table.j2
fi

if [ -f platform/vs/zero_profiles.j2 ]
then
    sudo cp platform/vs/zero_profiles.j2 $FILESYSTEM_ROOT/usr/share/sonic/templates/zero_profiles.j2
fi


# Copy backend acl template
sudo cp $BUILD_TEMPLATES/backend_acl.j2 $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/

# Copy hostname configuration scripts
sudo cp $IMAGE_CONFIGS/hostname/hostname-config.service $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM
echo "hostname-config.service" | sudo tee -a $GENERATED_SERVICE_FILE
sudo cp $IMAGE_CONFIGS/hostname/hostname-config.sh $FILESYSTEM_ROOT/usr/bin/

# Copy banner configuration scripts
sudo cp $IMAGE_CONFIGS/bannerconfig/banner-config.service $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM
echo "banner-config.service" | sudo tee -a $GENERATED_SERVICE_FILE
sudo cp $IMAGE_CONFIGS/bannerconfig/banner-config.sh $FILESYSTEM_ROOT/usr/bin/

# Copy miscellaneous scripts
sudo cp $IMAGE_CONFIGS/misc/docker-wait-any $FILESYSTEM_ROOT/usr/bin/

# Copy internal topology configuration scripts
sudo cp $IMAGE_CONFIGS/topology/topology.service $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM
echo "topology.service" | sudo tee -a $GENERATED_SERVICE_FILE
sudo cp $IMAGE_CONFIGS/topology/topology.sh $FILESYSTEM_ROOT/usr/bin

sudo cp platform/vs/dash-engine.service $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM
sudo LANG=C chroot $FILESYSTEM_ROOT systemctl disable dash-engine

# Copy platform topology configuration scripts
sudo cp $IMAGE_CONFIGS/config-topology/config-topology.service $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM
echo "config-topology.service" | sudo tee -a $GENERATED_SERVICE_FILE
sudo cp $IMAGE_CONFIGS/config-topology/config-topology.sh $FILESYSTEM_ROOT/usr/bin

# Generate initial SONiC configuration file
j2 files/build_templates/init_cfg.json.j2 | sudo tee $FILESYSTEM_ROOT/etc/sonic/init_cfg.json

# Copy config-setup script, conf file and service file
j2 files/build_templates/config-setup.service.j2 | sudo tee $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM/config-setup.service
sudo cp $IMAGE_CONFIGS/config-setup/config-setup $FILESYSTEM_ROOT/usr/bin/config-setup
sudo mkdir -p $FILESYSTEM_ROOT/etc/config-setup
sudo cp $IMAGE_CONFIGS/config-setup/config-setup.conf $FILESYSTEM_ROOT/etc/config-setup/config-setup.conf
echo "config-setup.service" | sudo tee -a $GENERATED_SERVICE_FILE
sudo LANG=C chroot $FILESYSTEM_ROOT systemctl enable config-setup.service

# Copy reset-factory script and service
sudo cp $IMAGE_CONFIGS/reset-factory/reset-factory $FILESYSTEM_ROOT/usr/bin/reset-factory

# Add delayed tacacs application service
sudo cp files/build_templates/tacacs-config.timer $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM/
echo "tacacs-config.timer" | sudo tee -a $GENERATED_SERVICE_FILE

sudo cp files/build_templates/tacacs-config.service $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM/
echo "tacacs-config.service" | sudo tee -a $GENERATED_SERVICE_FILE

# Copy config-chassisdb script and service file
j2 files/build_templates/config-chassisdb.service.j2 | sudo tee $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM/config-chassisdb.service
sudo cp $IMAGE_CONFIGS/config-chassisdb/config-chassisdb $FILESYSTEM_ROOT/usr/bin/config-chassisdb
echo "config-chassisdb.service" | sudo tee -a $GENERATED_SERVICE_FILE
sudo LANG=C chroot $FILESYSTEM_ROOT systemctl enable config-chassisdb.service

# Copy midplane network service file for smart switch
sudo cp $IMAGE_CONFIGS/midplane-network/bridge-midplane.netdev $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_NETWORK/bridge-midplane.netdev
sudo cp $IMAGE_CONFIGS/midplane-network/bridge-midplane.network $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_NETWORK/bridge-midplane.network
sudo cp $IMAGE_CONFIGS/midplane-network/dummy-midplane.netdev $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_NETWORK/dummy-midplane.netdev
sudo cp $IMAGE_CONFIGS/midplane-network/dummy-midplane.network $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_NETWORK/dummy-midplane.network
sudo cp $IMAGE_CONFIGS/midplane-network/midplane-network-npu.network $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_NETWORK/midplane-network-npu.network
sudo cp $IMAGE_CONFIGS/midplane-network/midplane-network-dpu.network $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_NETWORK/midplane-network-dpu.network
sudo cp $IMAGE_CONFIGS/midplane-network/midplane-network-npu.service $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM/midplane-network-npu.service
sudo cp $IMAGE_CONFIGS/midplane-network/midplane-network-dpu.service $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM/midplane-network-dpu.service

# Disable smart switch unit by default, these units will be controlled by systemd-sonic-generator
sudo ln -s /dev/null $FILESYSTEM_ROOT/etc/systemd/network/bridge-midplane.netdev
sudo ln -s /dev/null $FILESYSTEM_ROOT/etc/systemd/network/bridge-midplane.network
sudo ln -s /dev/null $FILESYSTEM_ROOT/etc/systemd/network/dummy-midplane.netdev
sudo ln -s /dev/null $FILESYSTEM_ROOT/etc/systemd/network/dummy-midplane.network
sudo ln -s /dev/null $FILESYSTEM_ROOT/etc/systemd/network/midplane-network-npu.network
sudo ln -s /dev/null $FILESYSTEM_ROOT/etc/systemd/network/midplane-network-dpu.network
echo "midplane-network-npu.service" | sudo tee -a $GENERATED_SERVICE_FILE
sudo LANG=C chroot $FILESYSTEM_ROOT systemctl disable midplane-network-npu.service
echo "midplane-network-dpu.service" | sudo tee -a $GENERATED_SERVICE_FILE
sudo LANG=C chroot $FILESYSTEM_ROOT systemctl disable midplane-network-dpu.service
sudo ln -s /dev/null $FILESYSTEM_ROOT/etc/systemd/system/dash-ha.service
sudo ln -s /dev/null $FILESYSTEM_ROOT/etc/systemd/system/dash-ha@dpu0.service
sudo ln -s /dev/null $FILESYSTEM_ROOT/etc/systemd/system/dash-ha@dpu1.service
sudo ln -s /dev/null $FILESYSTEM_ROOT/etc/systemd/system/dash-ha@dpu2.service
sudo ln -s /dev/null $FILESYSTEM_ROOT/etc/systemd/system/dash-ha@dpu3.service
sudo ln -s /dev/null $FILESYSTEM_ROOT/etc/systemd/system/dash-ha@dpu4.service
sudo ln -s /dev/null $FILESYSTEM_ROOT/etc/systemd/system/dash-ha@dpu5.service
sudo ln -s /dev/null $FILESYSTEM_ROOT/etc/systemd/system/dash-ha@dpu6.service
sudo ln -s /dev/null $FILESYSTEM_ROOT/etc/systemd/system/dash-ha@dpu7.service
# According to the issue: https://github.com/systemd/systemd/issues/19106, To disable ManageForeignRoutingPolicyRules to avoid the ip rules being deleted by systemd-networkd
sudo sed -i 's/#ManageForeignRoutingPolicyRules=yes/ManageForeignRoutingPolicyRules=no/g' $FILESYSTEM_ROOT/etc/systemd/networkd.conf

sudo ln -s /dev/null $FILESYSTEM_ROOT/etc/systemd/system/systemd-networkd.service
sudo LANG=C chroot $FILESYSTEM_ROOT systemctl disable systemd-networkd-wait-online.service

# Copy backend-acl script and service file
sudo cp $IMAGE_CONFIGS/backend_acl/backend-acl.service $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM/backend-acl.service
sudo cp $IMAGE_CONFIGS/backend_acl/backend_acl.py $FILESYSTEM_ROOT/usr/bin/backend_acl.py
echo "backend-acl.service" | sudo tee -a $GENERATED_SERVICE_FILE

# Copy RPS script file
sudo cp $IMAGE_CONFIGS/rps/rps.py $FILESYSTEM_ROOT/usr/bin/rps.py
sudo chmod 755 $FILESYSTEM_ROOT/usr/bin/rps.py

# Copy SNMP configuration files
sudo cp $IMAGE_CONFIGS/snmp/snmp.yml $FILESYSTEM_ROOT/etc/sonic/

# Copy ASN configuration files
sudo cp $IMAGE_CONFIGS/constants/constants.yml $FILESYSTEM_ROOT/etc/sonic/

# Copy sudoers configuration file
sudo cp $IMAGE_CONFIGS/sudoers/sudoers $FILESYSTEM_ROOT/etc/
sudo cp $IMAGE_CONFIGS/sudoers/sudoers.lecture $FILESYSTEM_ROOT/etc/

# Copy pcie-check service files
sudo cp $IMAGE_CONFIGS/pcie-check/pcie-check.service $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM
echo "pcie-check.service" | sudo tee -a $GENERATED_SERVICE_FILE
sudo cp $IMAGE_CONFIGS/pcie-check/pcie-check.sh $FILESYSTEM_ROOT/usr/bin/

## Install package without starting service
## ref: https://wiki.debian.org/chroot
sudo tee -a $FILESYSTEM_ROOT/usr/sbin/policy-rc.d > /dev/null <<EOF
#!/bin/sh
exit 101
EOF
sudo chmod a+x $FILESYSTEM_ROOT/usr/sbin/policy-rc.d

if [ "$INCLUDE_FIPS" == y ]; then
    sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-get -y install libatomic1
    # The package openssh-client 9.2 is conflict with FIPS, the line below can be removed when the openssh-client version>=9.4
    # The package will be reinstalled when isntalling the FIPS packages
    sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-get -y remove openssh-client
fi

install_deb_package target/debs/bookworm/systemd-sonic-generator_1.0.0_amd64.deb
install_deb_package target/debs/bookworm/libssl3_3.0.11-1~deb12u2+fips_amd64.deb
install_deb_package target/debs/bookworm/libssl-dev_3.0.11-1~deb12u2+fips_amd64.deb
install_deb_package target/debs/bookworm/openssl_3.0.11-1~deb12u2+fips_amd64.deb
install_deb_package target/debs/bookworm/symcrypt-openssl_1.5.2_amd64.deb
install_deb_package target/debs/bookworm/openssh-client_9.2p1-2+deb12u5+fips_amd64.deb
install_deb_package target/debs/bookworm/ssh_9.2p1-2+deb12u5+fips_all.deb
install_deb_package target/debs/bookworm/openssh-sftp-server_9.2p1-2+deb12u5+fips_amd64.deb
install_deb_package target/debs/bookworm/openssh-server_9.2p1-2+deb12u5+fips_amd64.deb
install_deb_package target/debs/bookworm/libk5crypto3_1.20.1-2+deb12u1+fips_amd64.deb



# For some SONiC patch packages, Debian offcial version may higher than SONiC version
# When install SONiC packages, fix broken install by 'apt-get -y install -f' may upgrade some installed SONiC packages to Debian offical version
# Check and install upgraded SONiC package again, if install failed, need manually check and fix SONiC package version issue
PACKAGE_NAME=$(dpkg-deb -f target/debs/bookworm/systemd-sonic-generator_1.0.0_amd64.deb Package)
PACKAGE_VERSION=$(dpkg-deb -f target/debs/bookworm/systemd-sonic-generator_1.0.0_amd64.deb Version)
INSTALLED_VERSION=$(dpkg-query --showformat='${Version}' --show $PACKAGE_NAME || true)
if [ "$INSTALLED_VERSION" != "" ] && [ "$INSTALLED_VERSION" != "$PACKAGE_VERSION" ]; then
    install_deb_package target/debs/bookworm/systemd-sonic-generator_1.0.0_amd64.deb
fi

## SONiC packages may have lower version than Debian offical package, install offical Debian package will break feature
## Hold installed packages to prevent these packages be upgrade by apt commands in this file
sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-mark hold $PACKAGE_NAME

# For some SONiC patch packages, Debian offcial version may higher than SONiC version
# When install SONiC packages, fix broken install by 'apt-get -y install -f' may upgrade some installed SONiC packages to Debian offical version
# Check and install upgraded SONiC package again, if install failed, need manually check and fix SONiC package version issue
PACKAGE_NAME=$(dpkg-deb -f target/debs/bookworm/libssl3_3.0.11-1~deb12u2+fips_amd64.deb Package)
PACKAGE_VERSION=$(dpkg-deb -f target/debs/bookworm/libssl3_3.0.11-1~deb12u2+fips_amd64.deb Version)
INSTALLED_VERSION=$(dpkg-query --showformat='${Version}' --show $PACKAGE_NAME || true)
if [ "$INSTALLED_VERSION" != "" ] && [ "$INSTALLED_VERSION" != "$PACKAGE_VERSION" ]; then
    install_deb_package target/debs/bookworm/libssl3_3.0.11-1~deb12u2+fips_amd64.deb
fi

## SONiC packages may have lower version than Debian offical package, install offical Debian package will break feature
## Hold installed packages to prevent these packages be upgrade by apt commands in this file
sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-mark hold $PACKAGE_NAME

# For some SONiC patch packages, Debian offcial version may higher than SONiC version
# When install SONiC packages, fix broken install by 'apt-get -y install -f' may upgrade some installed SONiC packages to Debian offical version
# Check and install upgraded SONiC package again, if install failed, need manually check and fix SONiC package version issue
PACKAGE_NAME=$(dpkg-deb -f target/debs/bookworm/libssl-dev_3.0.11-1~deb12u2+fips_amd64.deb Package)
PACKAGE_VERSION=$(dpkg-deb -f target/debs/bookworm/libssl-dev_3.0.11-1~deb12u2+fips_amd64.deb Version)
INSTALLED_VERSION=$(dpkg-query --showformat='${Version}' --show $PACKAGE_NAME || true)
if [ "$INSTALLED_VERSION" != "" ] && [ "$INSTALLED_VERSION" != "$PACKAGE_VERSION" ]; then
    install_deb_package target/debs/bookworm/libssl-dev_3.0.11-1~deb12u2+fips_amd64.deb
fi

## SONiC packages may have lower version than Debian offical package, install offical Debian package will break feature
## Hold installed packages to prevent these packages be upgrade by apt commands in this file
sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-mark hold $PACKAGE_NAME

# For some SONiC patch packages, Debian offcial version may higher than SONiC version
# When install SONiC packages, fix broken install by 'apt-get -y install -f' may upgrade some installed SONiC packages to Debian offical version
# Check and install upgraded SONiC package again, if install failed, need manually check and fix SONiC package version issue
PACKAGE_NAME=$(dpkg-deb -f target/debs/bookworm/openssl_3.0.11-1~deb12u2+fips_amd64.deb Package)
PACKAGE_VERSION=$(dpkg-deb -f target/debs/bookworm/openssl_3.0.11-1~deb12u2+fips_amd64.deb Version)
INSTALLED_VERSION=$(dpkg-query --showformat='${Version}' --show $PACKAGE_NAME || true)
if [ "$INSTALLED_VERSION" != "" ] && [ "$INSTALLED_VERSION" != "$PACKAGE_VERSION" ]; then
    install_deb_package target/debs/bookworm/openssl_3.0.11-1~deb12u2+fips_amd64.deb
fi

## SONiC packages may have lower version than Debian offical package, install offical Debian package will break feature
## Hold installed packages to prevent these packages be upgrade by apt commands in this file
sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-mark hold $PACKAGE_NAME

# For some SONiC patch packages, Debian offcial version may higher than SONiC version
# When install SONiC packages, fix broken install by 'apt-get -y install -f' may upgrade some installed SONiC packages to Debian offical version
# Check and install upgraded SONiC package again, if install failed, need manually check and fix SONiC package version issue
PACKAGE_NAME=$(dpkg-deb -f target/debs/bookworm/symcrypt-openssl_1.5.2_amd64.deb Package)
PACKAGE_VERSION=$(dpkg-deb -f target/debs/bookworm/symcrypt-openssl_1.5.2_amd64.deb Version)
INSTALLED_VERSION=$(dpkg-query --showformat='${Version}' --show $PACKAGE_NAME || true)
if [ "$INSTALLED_VERSION" != "" ] && [ "$INSTALLED_VERSION" != "$PACKAGE_VERSION" ]; then
    install_deb_package target/debs/bookworm/symcrypt-openssl_1.5.2_amd64.deb
fi

## SONiC packages may have lower version than Debian offical package, install offical Debian package will break feature
## Hold installed packages to prevent these packages be upgrade by apt commands in this file
sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-mark hold $PACKAGE_NAME

# For some SONiC patch packages, Debian offcial version may higher than SONiC version
# When install SONiC packages, fix broken install by 'apt-get -y install -f' may upgrade some installed SONiC packages to Debian offical version
# Check and install upgraded SONiC package again, if install failed, need manually check and fix SONiC package version issue
PACKAGE_NAME=$(dpkg-deb -f target/debs/bookworm/openssh-client_9.2p1-2+deb12u5+fips_amd64.deb Package)
PACKAGE_VERSION=$(dpkg-deb -f target/debs/bookworm/openssh-client_9.2p1-2+deb12u5+fips_amd64.deb Version)
INSTALLED_VERSION=$(dpkg-query --showformat='${Version}' --show $PACKAGE_NAME || true)
if [ "$INSTALLED_VERSION" != "" ] && [ "$INSTALLED_VERSION" != "$PACKAGE_VERSION" ]; then
    install_deb_package target/debs/bookworm/openssh-client_9.2p1-2+deb12u5+fips_amd64.deb
fi

## SONiC packages may have lower version than Debian offical package, install offical Debian package will break feature
## Hold installed packages to prevent these packages be upgrade by apt commands in this file
sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-mark hold $PACKAGE_NAME

# For some SONiC patch packages, Debian offcial version may higher than SONiC version
# When install SONiC packages, fix broken install by 'apt-get -y install -f' may upgrade some installed SONiC packages to Debian offical version
# Check and install upgraded SONiC package again, if install failed, need manually check and fix SONiC package version issue
PACKAGE_NAME=$(dpkg-deb -f target/debs/bookworm/ssh_9.2p1-2+deb12u5+fips_all.deb Package)
PACKAGE_VERSION=$(dpkg-deb -f target/debs/bookworm/ssh_9.2p1-2+deb12u5+fips_all.deb Version)
INSTALLED_VERSION=$(dpkg-query --showformat='${Version}' --show $PACKAGE_NAME || true)
if [ "$INSTALLED_VERSION" != "" ] && [ "$INSTALLED_VERSION" != "$PACKAGE_VERSION" ]; then
    install_deb_package target/debs/bookworm/ssh_9.2p1-2+deb12u5+fips_all.deb
fi

## SONiC packages may have lower version than Debian offical package, install offical Debian package will break feature
## Hold installed packages to prevent these packages be upgrade by apt commands in this file
sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-mark hold $PACKAGE_NAME

# For some SONiC patch packages, Debian offcial version may higher than SONiC version
# When install SONiC packages, fix broken install by 'apt-get -y install -f' may upgrade some installed SONiC packages to Debian offical version
# Check and install upgraded SONiC package again, if install failed, need manually check and fix SONiC package version issue
PACKAGE_NAME=$(dpkg-deb -f target/debs/bookworm/openssh-sftp-server_9.2p1-2+deb12u5+fips_amd64.deb Package)
PACKAGE_VERSION=$(dpkg-deb -f target/debs/bookworm/openssh-sftp-server_9.2p1-2+deb12u5+fips_amd64.deb Version)
INSTALLED_VERSION=$(dpkg-query --showformat='${Version}' --show $PACKAGE_NAME || true)
if [ "$INSTALLED_VERSION" != "" ] && [ "$INSTALLED_VERSION" != "$PACKAGE_VERSION" ]; then
    install_deb_package target/debs/bookworm/openssh-sftp-server_9.2p1-2+deb12u5+fips_amd64.deb
fi

## SONiC packages may have lower version than Debian offical package, install offical Debian package will break feature
## Hold installed packages to prevent these packages be upgrade by apt commands in this file
sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-mark hold $PACKAGE_NAME

# For some SONiC patch packages, Debian offcial version may higher than SONiC version
# When install SONiC packages, fix broken install by 'apt-get -y install -f' may upgrade some installed SONiC packages to Debian offical version
# Check and install upgraded SONiC package again, if install failed, need manually check and fix SONiC package version issue
PACKAGE_NAME=$(dpkg-deb -f target/debs/bookworm/openssh-server_9.2p1-2+deb12u5+fips_amd64.deb Package)
PACKAGE_VERSION=$(dpkg-deb -f target/debs/bookworm/openssh-server_9.2p1-2+deb12u5+fips_amd64.deb Version)
INSTALLED_VERSION=$(dpkg-query --showformat='${Version}' --show $PACKAGE_NAME || true)
if [ "$INSTALLED_VERSION" != "" ] && [ "$INSTALLED_VERSION" != "$PACKAGE_VERSION" ]; then
    install_deb_package target/debs/bookworm/openssh-server_9.2p1-2+deb12u5+fips_amd64.deb
fi

## SONiC packages may have lower version than Debian offical package, install offical Debian package will break feature
## Hold installed packages to prevent these packages be upgrade by apt commands in this file
sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-mark hold $PACKAGE_NAME

# For some SONiC patch packages, Debian offcial version may higher than SONiC version
# When install SONiC packages, fix broken install by 'apt-get -y install -f' may upgrade some installed SONiC packages to Debian offical version
# Check and install upgraded SONiC package again, if install failed, need manually check and fix SONiC package version issue
PACKAGE_NAME=$(dpkg-deb -f target/debs/bookworm/libk5crypto3_1.20.1-2+deb12u1+fips_amd64.deb Package)
PACKAGE_VERSION=$(dpkg-deb -f target/debs/bookworm/libk5crypto3_1.20.1-2+deb12u1+fips_amd64.deb Version)
INSTALLED_VERSION=$(dpkg-query --showformat='${Version}' --show $PACKAGE_NAME || true)
if [ "$INSTALLED_VERSION" != "" ] && [ "$INSTALLED_VERSION" != "$PACKAGE_VERSION" ]; then
    install_deb_package target/debs/bookworm/libk5crypto3_1.20.1-2+deb12u1+fips_amd64.deb
fi

## SONiC packages may have lower version than Debian offical package, install offical Debian package will break feature
## Hold installed packages to prevent these packages be upgrade by apt commands in this file
sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-mark hold $PACKAGE_NAME




## Run depmod command for target kernel modules
sudo LANG=C chroot $FILESYSTEM_ROOT depmod -a 6.1.0-29-2-amd64

## download all dependency packages for platform debian packages
install_deb_package_lazy target/debs/bookworm/sonic-platform-vs_1.0_amd64.deb

sudo mkdir -p $FILESYSTEM_ROOT/$PLATFORM_DIR/x86_64-kvm_x86_64-r0
sudo mkdir -p $FILESYSTEM_ROOT/$PLATFORM_DIR/common
sudo cp target/debs/bookworm/sonic-platform-vs_1.0_amd64.deb $FILESYSTEM_ROOT/$PLATFORM_DIR/common/
sudo ln -sf "../common/sonic-platform-vs_1.0_amd64.deb" "$FILESYSTEM_ROOT/$PLATFORM_DIR/x86_64-kvm_x86_64-r0/sonic-platform-vs_1.0_amd64.deb"
for f in $(find $FILESYSTEM_ROOT/var/cache/apt/archives -name "*.deb"); do
    sudo mv $f $FILESYSTEM_ROOT/$PLATFORM_DIR/common/
    sudo ln -sf "../common/$(basename $f)" "$FILESYSTEM_ROOT/$PLATFORM_DIR/x86_64-kvm_x86_64-r0/$(basename $f)"
done

sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT dpkg -P sonic-platform-vs


# create a trivial apt repo if any of the debs have dependencies, including between lazy debs
if [ $(for f in $FILESYSTEM_ROOT/$PLATFORM_DIR/common/*.deb; do \
           sudo dpkg -I $f | grep "Depends:\|Pre-Depends:"; done | wc -l) -gt 0 ]; then
    (cd $FILESYSTEM_ROOT/$PLATFORM_DIR/common && sudo dpkg-scanpackages . | \
         sudo gzip | sudo tee Packages.gz > /dev/null)
fi


# Remove sshd host keys, and will regenerate on first sshd start. This needs to be
# done again here because our custom version of sshd is being installed, which
# will regenerate the sshd host keys.
sudo rm -f $FILESYSTEM_ROOT/etc/ssh/ssh_host_*_key*

sudo rm -f $FILESYSTEM_ROOT/usr/sbin/policy-rc.d

# Copy fstrim service and timer file, enable fstrim timer
sudo cp $IMAGE_CONFIGS/fstrim/* $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM
sudo LANG=C chroot $FILESYSTEM_ROOT systemctl enable fstrim.timer

## copy platform rc.local
sudo cp $IMAGE_CONFIGS/platform/rc.local $FILESYSTEM_ROOT/etc/

## copy blacklist file
sudo cp $IMAGE_CONFIGS/platform/linux_kernel_bde.conf $FILESYSTEM_ROOT/etc/modprobe.d/

# Enable psample drivers to support sFlow on vs

sudo tee -a $FILESYSTEM_ROOT/etc/modules-load.d/modules.conf > /dev/null <<EOF
psample
act_sample
EOF


## Bind docker path
if [[ $MULTIARCH_QEMU_ENVIRON == y || $CROSS_BUILD_ENVIRON == y ]]; then
    sudo mkdir -p $FILESYSTEM_ROOT/dockerfs
    sudo mount --bind dockerfs $FILESYSTEM_ROOT/dockerfs
fi

## ensure proc is mounted
sudo mount proc /proc -t proc || true
if [[ $CONFIGURED_ARCH == armhf ]]; then
    # A workaround to fix the armhf build hung issue, caused by sonic-platform-nokia-7215_1.0_armhf.deb post installation script
    ps -eo pid,cmd | grep python | grep "/etc/entropy.py" | awk '{print $1}' | xargs sudo kill -9 2>/dev/null || true
fi

sudo mkdir $FILESYSTEM_ROOT/target
sudo mount --bind target $FILESYSTEM_ROOT/target
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker info


if [[ -z "" || -n "" && $TARGET_MACHINE == "" ]]; then
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker load -i target/docker-auditd-watchdog-dbg.gz
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-auditd-watchdog-dbg:latest docker-auditd-watchdog-dbg:"${SONIC_IMAGE_VERSION}"
# Check if manifest exists for docker-auditd-watchdog-dbg and it is a valid JSON
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker inspect docker-auditd-watchdog-dbg:latest \
    | jq '.[0].Config.Labels["com.azure.sonic.manifest"]' -r > /tmp/manifest.json
jq -e . /tmp/manifest.json || {
    >&2 echo "docker image docker-auditd-watchdog-dbg has no manifest or manifest is not a valid JSON"
    exit 1
}

sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-auditd-watchdog-dbg:latest docker-auditd-watchdog:"${SONIC_IMAGE_VERSION}"
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-auditd-watchdog-dbg:latest docker-auditd-watchdog:latest

fi

if [[ -z "" || -n "" && $TARGET_MACHINE == "" ]]; then
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker load -i target/docker-auditd-dbg.gz
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-auditd-dbg:latest docker-auditd-dbg:"${SONIC_IMAGE_VERSION}"
# Check if manifest exists for docker-auditd-dbg and it is a valid JSON
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker inspect docker-auditd-dbg:latest \
    | jq '.[0].Config.Labels["com.azure.sonic.manifest"]' -r > /tmp/manifest.json
jq -e . /tmp/manifest.json || {
    >&2 echo "docker image docker-auditd-dbg has no manifest or manifest is not a valid JSON"
    exit 1
}

sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-auditd-dbg:latest docker-auditd:"${SONIC_IMAGE_VERSION}"
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-auditd-dbg:latest docker-auditd:latest

fi

if [[ -z "" || -n "" && $TARGET_MACHINE == "" ]]; then
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker load -i target/docker-bmp-watchdog-dbg.gz
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-bmp-watchdog-dbg:latest docker-bmp-watchdog-dbg:"${SONIC_IMAGE_VERSION}"
# Check if manifest exists for docker-bmp-watchdog-dbg and it is a valid JSON
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker inspect docker-bmp-watchdog-dbg:latest \
    | jq '.[0].Config.Labels["com.azure.sonic.manifest"]' -r > /tmp/manifest.json
jq -e . /tmp/manifest.json || {
    >&2 echo "docker image docker-bmp-watchdog-dbg has no manifest or manifest is not a valid JSON"
    exit 1
}

sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-bmp-watchdog-dbg:latest docker-bmp-watchdog:"${SONIC_IMAGE_VERSION}"
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-bmp-watchdog-dbg:latest docker-bmp-watchdog:latest

fi

if [[ -z "" || -n "" && $TARGET_MACHINE == "" ]]; then
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker load -i target/docker-database-dbg.gz
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-database-dbg:latest docker-database-dbg:"${SONIC_IMAGE_VERSION}"
# Check if manifest exists for docker-database-dbg and it is a valid JSON
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker inspect docker-database-dbg:latest \
    | jq '.[0].Config.Labels["com.azure.sonic.manifest"]' -r > /tmp/manifest.json
jq -e . /tmp/manifest.json || {
    >&2 echo "docker image docker-database-dbg has no manifest or manifest is not a valid JSON"
    exit 1
}

sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-database-dbg:latest docker-database:"${SONIC_IMAGE_VERSION}"
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-database-dbg:latest docker-database:latest

fi

if [[ -z "" || -n "" && $TARGET_MACHINE == "" ]]; then
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker load -i target/docker-fpm-frr-dbg.gz
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-fpm-frr-dbg:latest docker-fpm-frr-dbg:"${SONIC_IMAGE_VERSION}"
# Check if manifest exists for docker-fpm-frr-dbg and it is a valid JSON
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker inspect docker-fpm-frr-dbg:latest \
    | jq '.[0].Config.Labels["com.azure.sonic.manifest"]' -r > /tmp/manifest.json
jq -e . /tmp/manifest.json || {
    >&2 echo "docker image docker-fpm-frr-dbg has no manifest or manifest is not a valid JSON"
    exit 1
}

sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-fpm-frr-dbg:latest docker-fpm-frr:"${SONIC_IMAGE_VERSION}"
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-fpm-frr-dbg:latest docker-fpm-frr:latest

fi

if [[ -z "" || -n "" && $TARGET_MACHINE == "" ]]; then
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker load -i target/docker-gnmi-watchdog-dbg.gz
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-gnmi-watchdog-dbg:latest docker-gnmi-watchdog-dbg:"${SONIC_IMAGE_VERSION}"
# Check if manifest exists for docker-gnmi-watchdog-dbg and it is a valid JSON
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker inspect docker-gnmi-watchdog-dbg:latest \
    | jq '.[0].Config.Labels["com.azure.sonic.manifest"]' -r > /tmp/manifest.json
jq -e . /tmp/manifest.json || {
    >&2 echo "docker image docker-gnmi-watchdog-dbg has no manifest or manifest is not a valid JSON"
    exit 1
}

sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-gnmi-watchdog-dbg:latest docker-gnmi-watchdog:"${SONIC_IMAGE_VERSION}"
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-gnmi-watchdog-dbg:latest docker-gnmi-watchdog:latest

fi

if [[ -z "" || -n "" && $TARGET_MACHINE == "" ]]; then
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker load -i target/docker-sonic-gnmi-dbg.gz
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-sonic-gnmi-dbg:latest docker-sonic-gnmi-dbg:"${SONIC_IMAGE_VERSION}"
# Check if manifest exists for docker-sonic-gnmi-dbg and it is a valid JSON
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker inspect docker-sonic-gnmi-dbg:latest \
    | jq '.[0].Config.Labels["com.azure.sonic.manifest"]' -r > /tmp/manifest.json
jq -e . /tmp/manifest.json || {
    >&2 echo "docker image docker-sonic-gnmi-dbg has no manifest or manifest is not a valid JSON"
    exit 1
}

sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-sonic-gnmi-dbg:latest docker-sonic-gnmi:"${SONIC_IMAGE_VERSION}"
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-sonic-gnmi-dbg:latest docker-sonic-gnmi:latest

fi

if [[ -z "" || -n "" && $TARGET_MACHINE == "" ]]; then
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker load -i target/docker-lldp-dbg.gz
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-lldp-dbg:latest docker-lldp-dbg:"${SONIC_IMAGE_VERSION}"
# Check if manifest exists for docker-lldp-dbg and it is a valid JSON
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker inspect docker-lldp-dbg:latest \
    | jq '.[0].Config.Labels["com.azure.sonic.manifest"]' -r > /tmp/manifest.json
jq -e . /tmp/manifest.json || {
    >&2 echo "docker image docker-lldp-dbg has no manifest or manifest is not a valid JSON"
    exit 1
}

sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-lldp-dbg:latest docker-lldp:"${SONIC_IMAGE_VERSION}"
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-lldp-dbg:latest docker-lldp:latest

fi

if [[ -z "" || -n "" && $TARGET_MACHINE == "" ]]; then
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker load -i target/docker-mux-dbg.gz
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-mux-dbg:latest docker-mux-dbg:"${SONIC_IMAGE_VERSION}"
# Check if manifest exists for docker-mux-dbg and it is a valid JSON
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker inspect docker-mux-dbg:latest \
    | jq '.[0].Config.Labels["com.azure.sonic.manifest"]' -r > /tmp/manifest.json
jq -e . /tmp/manifest.json || {
    >&2 echo "docker image docker-mux-dbg has no manifest or manifest is not a valid JSON"
    exit 1
}

sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-mux-dbg:latest docker-mux:"${SONIC_IMAGE_VERSION}"
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-mux-dbg:latest docker-mux:latest

fi

if [[ -z "" || -n "" && $TARGET_MACHINE == "" ]]; then
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker load -i target/docker-orchagent-dbg.gz
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-orchagent-dbg:latest docker-orchagent-dbg:"${SONIC_IMAGE_VERSION}"
# Check if manifest exists for docker-orchagent-dbg and it is a valid JSON
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker inspect docker-orchagent-dbg:latest \
    | jq '.[0].Config.Labels["com.azure.sonic.manifest"]' -r > /tmp/manifest.json
jq -e . /tmp/manifest.json || {
    >&2 echo "docker image docker-orchagent-dbg has no manifest or manifest is not a valid JSON"
    exit 1
}

sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-orchagent-dbg:latest docker-orchagent:"${SONIC_IMAGE_VERSION}"
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-orchagent-dbg:latest docker-orchagent:latest

fi

if [[ -z "" || -n "" && $TARGET_MACHINE == "" ]]; then
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker load -i target/docker-platform-monitor-dbg.gz
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-platform-monitor-dbg:latest docker-platform-monitor-dbg:"${SONIC_IMAGE_VERSION}"
# Check if manifest exists for docker-platform-monitor-dbg and it is a valid JSON
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker inspect docker-platform-monitor-dbg:latest \
    | jq '.[0].Config.Labels["com.azure.sonic.manifest"]' -r > /tmp/manifest.json
jq -e . /tmp/manifest.json || {
    >&2 echo "docker image docker-platform-monitor-dbg has no manifest or manifest is not a valid JSON"
    exit 1
}

sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-platform-monitor-dbg:latest docker-platform-monitor:"${SONIC_IMAGE_VERSION}"
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-platform-monitor-dbg:latest docker-platform-monitor:latest

fi

if [[ -z "" || -n "" && $TARGET_MACHINE == "" ]]; then
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker load -i target/docker-sflow-dbg.gz
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-sflow-dbg:latest docker-sflow-dbg:"${SONIC_IMAGE_VERSION}"
# Check if manifest exists for docker-sflow-dbg and it is a valid JSON
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker inspect docker-sflow-dbg:latest \
    | jq '.[0].Config.Labels["com.azure.sonic.manifest"]' -r > /tmp/manifest.json
jq -e . /tmp/manifest.json || {
    >&2 echo "docker image docker-sflow-dbg has no manifest or manifest is not a valid JSON"
    exit 1
}

sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-sflow-dbg:latest docker-sflow:"${SONIC_IMAGE_VERSION}"
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-sflow-dbg:latest docker-sflow:latest

fi

if [[ -z "" || -n "" && $TARGET_MACHINE == "" ]]; then
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker load -i target/docker-snmp-dbg.gz
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-snmp-dbg:latest docker-snmp-dbg:"${SONIC_IMAGE_VERSION}"
# Check if manifest exists for docker-snmp-dbg and it is a valid JSON
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker inspect docker-snmp-dbg:latest \
    | jq '.[0].Config.Labels["com.azure.sonic.manifest"]' -r > /tmp/manifest.json
jq -e . /tmp/manifest.json || {
    >&2 echo "docker image docker-snmp-dbg has no manifest or manifest is not a valid JSON"
    exit 1
}

sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-snmp-dbg:latest docker-snmp:"${SONIC_IMAGE_VERSION}"
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-snmp-dbg:latest docker-snmp:latest

fi

if [[ -z "" || -n "" && $TARGET_MACHINE == "" ]]; then
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker load -i target/docker-sonic-mgmt-framework-dbg.gz
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-sonic-mgmt-framework-dbg:latest docker-sonic-mgmt-framework-dbg:"${SONIC_IMAGE_VERSION}"
# Check if manifest exists for docker-sonic-mgmt-framework-dbg and it is a valid JSON
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker inspect docker-sonic-mgmt-framework-dbg:latest \
    | jq '.[0].Config.Labels["com.azure.sonic.manifest"]' -r > /tmp/manifest.json
jq -e . /tmp/manifest.json || {
    >&2 echo "docker image docker-sonic-mgmt-framework-dbg has no manifest or manifest is not a valid JSON"
    exit 1
}

sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-sonic-mgmt-framework-dbg:latest docker-sonic-mgmt-framework:"${SONIC_IMAGE_VERSION}"
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-sonic-mgmt-framework-dbg:latest docker-sonic-mgmt-framework:latest

fi

if [[ -z "" || -n "" && $TARGET_MACHINE == "" ]]; then
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker load -i target/docker-stp-dbg.gz
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-stp-dbg:latest docker-stp-dbg:"${SONIC_IMAGE_VERSION}"
# Check if manifest exists for docker-stp-dbg and it is a valid JSON
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker inspect docker-stp-dbg:latest \
    | jq '.[0].Config.Labels["com.azure.sonic.manifest"]' -r > /tmp/manifest.json
jq -e . /tmp/manifest.json || {
    >&2 echo "docker image docker-stp-dbg has no manifest or manifest is not a valid JSON"
    exit 1
}

sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-stp-dbg:latest docker-stp:"${SONIC_IMAGE_VERSION}"
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-stp-dbg:latest docker-stp:latest

fi

if [[ -z "" || -n "" && $TARGET_MACHINE == "" ]]; then
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker load -i target/docker-sysmgr-dbg.gz
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-sysmgr-dbg:latest docker-sysmgr-dbg:"${SONIC_IMAGE_VERSION}"
# Check if manifest exists for docker-sysmgr-dbg and it is a valid JSON
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker inspect docker-sysmgr-dbg:latest \
    | jq '.[0].Config.Labels["com.azure.sonic.manifest"]' -r > /tmp/manifest.json
jq -e . /tmp/manifest.json || {
    >&2 echo "docker image docker-sysmgr-dbg has no manifest or manifest is not a valid JSON"
    exit 1
}

sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-sysmgr-dbg:latest docker-sysmgr:"${SONIC_IMAGE_VERSION}"
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-sysmgr-dbg:latest docker-sysmgr:latest

fi

if [[ -z "" || -n "" && $TARGET_MACHINE == "" ]]; then
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker load -i target/docker-teamd-dbg.gz
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-teamd-dbg:latest docker-teamd-dbg:"${SONIC_IMAGE_VERSION}"
# Check if manifest exists for docker-teamd-dbg and it is a valid JSON
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker inspect docker-teamd-dbg:latest \
    | jq '.[0].Config.Labels["com.azure.sonic.manifest"]' -r > /tmp/manifest.json
jq -e . /tmp/manifest.json || {
    >&2 echo "docker image docker-teamd-dbg has no manifest or manifest is not a valid JSON"
    exit 1
}

sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-teamd-dbg:latest docker-teamd:"${SONIC_IMAGE_VERSION}"
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-teamd-dbg:latest docker-teamd:latest

fi

if [[ -z "" || -n "" && $TARGET_MACHINE == "" ]]; then
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker load -i target/docker-syncd-vs-dbg.gz
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-syncd-vs-dbg:latest docker-syncd-vs-dbg:"${SONIC_IMAGE_VERSION}"
# Check if manifest exists for docker-syncd-vs-dbg and it is a valid JSON
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker inspect docker-syncd-vs-dbg:latest \
    | jq '.[0].Config.Labels["com.azure.sonic.manifest"]' -r > /tmp/manifest.json
jq -e . /tmp/manifest.json || {
    >&2 echo "docker image docker-syncd-vs-dbg has no manifest or manifest is not a valid JSON"
    exit 1
}

sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-syncd-vs-dbg:latest docker-syncd-vs:"${SONIC_IMAGE_VERSION}"
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-syncd-vs-dbg:latest docker-syncd-vs:latest

fi

if [[ -z "" || -n "" && $TARGET_MACHINE == "" ]]; then
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker load -i target/docker-gbsyncd-vs-dbg.gz
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-gbsyncd-vs-dbg:latest docker-gbsyncd-vs-dbg:"${SONIC_IMAGE_VERSION}"
# Check if manifest exists for docker-gbsyncd-vs-dbg and it is a valid JSON
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker inspect docker-gbsyncd-vs-dbg:latest \
    | jq '.[0].Config.Labels["com.azure.sonic.manifest"]' -r > /tmp/manifest.json
jq -e . /tmp/manifest.json || {
    >&2 echo "docker image docker-gbsyncd-vs-dbg has no manifest or manifest is not a valid JSON"
    exit 1
}

sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-gbsyncd-vs-dbg:latest docker-gbsyncd-vs:"${SONIC_IMAGE_VERSION}"
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-gbsyncd-vs-dbg:latest docker-gbsyncd-vs:latest

fi

if [[ -z "" || -n "" && $TARGET_MACHINE == "" ]]; then
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker load -i target/docker-dash-engine.gz
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag docker-dash-engine:latest docker-dash-engine:"${SONIC_IMAGE_VERSION}"
# Check if manifest exists for docker-dash-engine and it is a valid JSON
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker inspect docker-dash-engine:latest \
    | jq '.[0].Config.Labels["com.azure.sonic.manifest"]' -r > /tmp/manifest.json
jq -e . /tmp/manifest.json || {
    >&2 echo "docker image docker-dash-engine has no manifest or manifest is not a valid JSON"
    exit 1
}

fi


if [[ $CONFIGURED_PLATFORM == pensando ]]; then
#Disable rc.local
sudo LANG=C chroot $FILESYSTEM_ROOT chmod -x /etc/rc.local
sudo cp files/dsc/dpu.service $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM/
sudo cp files/dsc/dpu.init $FILESYSTEM_ROOT/etc/init.d/dpu
sudo LANG=C chroot $FILESYSTEM_ROOT systemctl enable dpu.service
fi

SONIC_PACKAGE_MANAGER_FOLDER="/var/lib/sonic-package-manager/"
sudo mkdir -p $FILESYSTEM_ROOT/$SONIC_PACKAGE_MANAGER_FOLDER
target_machine="$TARGET_MACHINE" j2 $BUILD_TEMPLATES/packages.json.j2 | sudo tee $FILESYSTEM_ROOT/$SONIC_PACKAGE_MANAGER_FOLDER/packages.json
if [ "${PIPESTATUS[0]}" != "0" ]; then
    echo "Failed to generate packages.json" >&2
    exit 1
fi

#Copy the default manifest file to SONIC_PACKAGE_MANAGER_FOLDER directly
sudo cp $BUILD_TEMPLATES/default_manifest $FILESYSTEM_ROOT/$SONIC_PACKAGE_MANAGER_FOLDER/default_manifest
#Create a new manifests subdirectory under SONIC_PACKAGE_MANAGER_FOLDER for all the user created custom manifests
sudo mkdir -p $FILESYSTEM_ROOT/$SONIC_PACKAGE_MANAGER_FOLDER/manifests

# Copy docker_image_ctl.j2 for SONiC Package Manager
sudo cp $BUILD_TEMPLATES/docker_image_ctl.j2 $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/docker_image_ctl.j2

# Generate shutdown order
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT /usr/local/bin/generate_shutdown_order.py





sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT sonic-package-manager install --from-tarball target/docker-macsec-dbg.gz -y -v DEBUG

name_repo=$(basename docker-macsec-dbg.gz .gz)
sudo LANG=C DOCKER_HOST="$DOCKER_HOST" chroot $FILESYSTEM_ROOT docker tag $name_repo:latest $name_repo:"${SONIC_IMAGE_VERSION}"
sudo umount $FILESYSTEM_ROOT/target
sudo rm -r $FILESYSTEM_ROOT/target
if [[ $MULTIARCH_QEMU_ENVIRON == y || $CROSS_BUILD_ENVIRON == y ]]; then
    sudo umount $FILESYSTEM_ROOT/dockerfs
    sudo rm -fr $FILESYSTEM_ROOT/dockerfs
    sudo kill -9 `sudo $SONIC_NATIVE_DOCKERD_FOR_DOCKERFS_PID` || true
else
    sudo chroot $FILESYSTEM_ROOT $DOCKER_CTL_SCRIPT stop
fi

sudo bash -c "echo { > $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/ctr_image_names.json"




    sudo bash -c "echo -n -e \"\x22auditd_watchdog\x22 : \x22docker-auditd-watchdog\x22\" >> $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/ctr_image_names.json"

    sudo bash -c "echo \",\" >> $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/ctr_image_names.json"






    sudo bash -c "echo -n -e \"\x22auditd\x22 : \x22docker-auditd\x22\" >> $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/ctr_image_names.json"

    sudo bash -c "echo \",\" >> $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/ctr_image_names.json"






    sudo bash -c "echo -n -e \"\x22bmp_watchdog\x22 : \x22docker-bmp-watchdog\x22\" >> $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/ctr_image_names.json"

    sudo bash -c "echo \",\" >> $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/ctr_image_names.json"






    sudo bash -c "echo -n -e \"\x22database\x22 : \x22docker-database\x22\" >> $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/ctr_image_names.json"

    sudo bash -c "echo \",\" >> $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/ctr_image_names.json"






    sudo bash -c "echo -n -e \"\x22bgp\x22 : \x22docker-fpm-frr\x22\" >> $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/ctr_image_names.json"

    sudo bash -c "echo \",\" >> $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/ctr_image_names.json"






    sudo bash -c "echo -n -e \"\x22gnmi_watchdog\x22 : \x22docker-gnmi-watchdog\x22\" >> $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/ctr_image_names.json"

    sudo bash -c "echo \",\" >> $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/ctr_image_names.json"






    sudo bash -c "echo -n -e \"\x22gnmi\x22 : \x22docker-sonic-gnmi\x22\" >> $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/ctr_image_names.json"

    sudo bash -c "echo \",\" >> $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/ctr_image_names.json"






    sudo bash -c "echo -n -e \"\x22lldp\x22 : \x22docker-lldp\x22\" >> $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/ctr_image_names.json"

    sudo bash -c "echo \",\" >> $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/ctr_image_names.json"






    sudo bash -c "echo -n -e \"\x22mux\x22 : \x22docker-mux\x22\" >> $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/ctr_image_names.json"

    sudo bash -c "echo \",\" >> $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/ctr_image_names.json"






    sudo bash -c "echo -n -e \"\x22swss\x22 : \x22docker-orchagent\x22\" >> $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/ctr_image_names.json"

    sudo bash -c "echo \",\" >> $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/ctr_image_names.json"






    sudo bash -c "echo -n -e \"\x22pmon\x22 : \x22docker-platform-monitor\x22\" >> $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/ctr_image_names.json"

    sudo bash -c "echo \",\" >> $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/ctr_image_names.json"






    sudo bash -c "echo -n -e \"\x22sflow\x22 : \x22docker-sflow\x22\" >> $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/ctr_image_names.json"

    sudo bash -c "echo \",\" >> $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/ctr_image_names.json"






    sudo bash -c "echo -n -e \"\x22snmp\x22 : \x22docker-snmp\x22\" >> $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/ctr_image_names.json"

    sudo bash -c "echo \",\" >> $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/ctr_image_names.json"






    sudo bash -c "echo -n -e \"\x22mgmt-framework\x22 : \x22docker-sonic-mgmt-framework\x22\" >> $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/ctr_image_names.json"

    sudo bash -c "echo \",\" >> $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/ctr_image_names.json"






    sudo bash -c "echo -n -e \"\x22stp\x22 : \x22docker-stp\x22\" >> $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/ctr_image_names.json"

    sudo bash -c "echo \",\" >> $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/ctr_image_names.json"






    sudo bash -c "echo -n -e \"\x22sysmgr\x22 : \x22docker-sysmgr\x22\" >> $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/ctr_image_names.json"

    sudo bash -c "echo \",\" >> $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/ctr_image_names.json"






    sudo bash -c "echo -n -e \"\x22teamd\x22 : \x22docker-teamd\x22\" >> $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/ctr_image_names.json"

    sudo bash -c "echo \",\" >> $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/ctr_image_names.json"






    sudo bash -c "echo -n -e \"\x22syncd\x22 : \x22docker-syncd-vs\x22\" >> $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/ctr_image_names.json"

    sudo bash -c "echo \",\" >> $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/ctr_image_names.json"






    sudo bash -c "echo -n -e \"\x22gbsyncd\x22 : \x22docker-gbsyncd-vs\x22\" >> $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/ctr_image_names.json"

    sudo bash -c "echo \",\" >> $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/ctr_image_names.json"






    sudo bash -c "echo -n -e \"\x22dash_engine\x22 : \x22docker-dash-engine\x22\" >> $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/ctr_image_names.json"

    sudo bash -c "echo \"\" >> $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/ctr_image_names.json"



sudo bash -c "echo } >> $FILESYSTEM_ROOT_USR_SHARE_SONIC_TEMPLATES/ctr_image_names.json"

if [ -f $TARGET_MACHINE"_auditd_watchdog.sh" ]; then
    sudo cp $TARGET_MACHINE"_auditd_watchdog.sh" $FILESYSTEM_ROOT/usr/bin/auditd_watchdog.sh
else
    sudo cp auditd_watchdog.sh $FILESYSTEM_ROOT/usr/bin/
fi
if [ -f $TARGET_MACHINE"_auditd.sh" ]; then
    sudo cp $TARGET_MACHINE"_auditd.sh" $FILESYSTEM_ROOT/usr/bin/auditd.sh
else
    sudo cp auditd.sh $FILESYSTEM_ROOT/usr/bin/
fi
if [ -f $TARGET_MACHINE"_bmp_watchdog.sh" ]; then
    sudo cp $TARGET_MACHINE"_bmp_watchdog.sh" $FILESYSTEM_ROOT/usr/bin/bmp_watchdog.sh
else
    sudo cp bmp_watchdog.sh $FILESYSTEM_ROOT/usr/bin/
fi
if [ -f $TARGET_MACHINE"_database.sh" ]; then
    sudo cp $TARGET_MACHINE"_database.sh" $FILESYSTEM_ROOT/usr/bin/database.sh
else
    sudo cp database.sh $FILESYSTEM_ROOT/usr/bin/
fi
if [ -f $TARGET_MACHINE"_bgp.sh" ]; then
    sudo cp $TARGET_MACHINE"_bgp.sh" $FILESYSTEM_ROOT/usr/bin/bgp.sh
else
    sudo cp bgp.sh $FILESYSTEM_ROOT/usr/bin/
fi
if [ -f $TARGET_MACHINE"_gnmi_watchdog.sh" ]; then
    sudo cp $TARGET_MACHINE"_gnmi_watchdog.sh" $FILESYSTEM_ROOT/usr/bin/gnmi_watchdog.sh
else
    sudo cp gnmi_watchdog.sh $FILESYSTEM_ROOT/usr/bin/
fi
if [ -f $TARGET_MACHINE"_gnmi.sh" ]; then
    sudo cp $TARGET_MACHINE"_gnmi.sh" $FILESYSTEM_ROOT/usr/bin/gnmi.sh
else
    sudo cp gnmi.sh $FILESYSTEM_ROOT/usr/bin/
fi
if [ -f $TARGET_MACHINE"_lldp.sh" ]; then
    sudo cp $TARGET_MACHINE"_lldp.sh" $FILESYSTEM_ROOT/usr/bin/lldp.sh
else
    sudo cp lldp.sh $FILESYSTEM_ROOT/usr/bin/
fi
if [ -f $TARGET_MACHINE"_mux.sh" ]; then
    sudo cp $TARGET_MACHINE"_mux.sh" $FILESYSTEM_ROOT/usr/bin/mux.sh
else
    sudo cp mux.sh $FILESYSTEM_ROOT/usr/bin/
fi
if [ -f $TARGET_MACHINE"_swss.sh" ]; then
    sudo cp $TARGET_MACHINE"_swss.sh" $FILESYSTEM_ROOT/usr/bin/swss.sh
else
    sudo cp swss.sh $FILESYSTEM_ROOT/usr/bin/
fi
if [ -f $TARGET_MACHINE"_pmon.sh" ]; then
    sudo cp $TARGET_MACHINE"_pmon.sh" $FILESYSTEM_ROOT/usr/bin/pmon.sh
else
    sudo cp pmon.sh $FILESYSTEM_ROOT/usr/bin/
fi
if [ -f $TARGET_MACHINE"_sflow.sh" ]; then
    sudo cp $TARGET_MACHINE"_sflow.sh" $FILESYSTEM_ROOT/usr/bin/sflow.sh
else
    sudo cp sflow.sh $FILESYSTEM_ROOT/usr/bin/
fi
if [ -f $TARGET_MACHINE"_snmp.sh" ]; then
    sudo cp $TARGET_MACHINE"_snmp.sh" $FILESYSTEM_ROOT/usr/bin/snmp.sh
else
    sudo cp snmp.sh $FILESYSTEM_ROOT/usr/bin/
fi
if [ -f $TARGET_MACHINE"_mgmt-framework.sh" ]; then
    sudo cp $TARGET_MACHINE"_mgmt-framework.sh" $FILESYSTEM_ROOT/usr/bin/mgmt-framework.sh
else
    sudo cp mgmt-framework.sh $FILESYSTEM_ROOT/usr/bin/
fi
if [ -f $TARGET_MACHINE"_stp.sh" ]; then
    sudo cp $TARGET_MACHINE"_stp.sh" $FILESYSTEM_ROOT/usr/bin/stp.sh
else
    sudo cp stp.sh $FILESYSTEM_ROOT/usr/bin/
fi
if [ -f $TARGET_MACHINE"_sysmgr.sh" ]; then
    sudo cp $TARGET_MACHINE"_sysmgr.sh" $FILESYSTEM_ROOT/usr/bin/sysmgr.sh
else
    sudo cp sysmgr.sh $FILESYSTEM_ROOT/usr/bin/
fi
if [ -f $TARGET_MACHINE"_teamd.sh" ]; then
    sudo cp $TARGET_MACHINE"_teamd.sh" $FILESYSTEM_ROOT/usr/bin/teamd.sh
else
    sudo cp teamd.sh $FILESYSTEM_ROOT/usr/bin/
fi
if [ -f $TARGET_MACHINE"_syncd.sh" ]; then
    sudo cp $TARGET_MACHINE"_syncd.sh" $FILESYSTEM_ROOT/usr/bin/syncd.sh
else
    sudo cp syncd.sh $FILESYSTEM_ROOT/usr/bin/
fi
if [ -f $TARGET_MACHINE"_gbsyncd.sh" ]; then
    sudo cp $TARGET_MACHINE"_gbsyncd.sh" $FILESYSTEM_ROOT/usr/bin/gbsyncd.sh
else
    sudo cp gbsyncd.sh $FILESYSTEM_ROOT/usr/bin/
fi
if [ -f $TARGET_MACHINE"_dash_engine.sh" ]; then
    sudo cp $TARGET_MACHINE"_dash_engine.sh" $FILESYSTEM_ROOT/usr/bin/dash_engine.sh
else
    sudo cp dash_engine.sh $FILESYSTEM_ROOT/usr/bin/
fi

if [ -f auditd_watchdog.service ]; then
    sudo cp auditd_watchdog.service $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM

    

    echo "auditd_watchdog.service" | sudo tee -a $GENERATED_SERVICE_FILE
fi
if [ -f auditd.service ]; then
    sudo cp auditd.service $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM

    

    echo "auditd.service" | sudo tee -a $GENERATED_SERVICE_FILE
fi
if [ -f bmp_watchdog.service ]; then
    sudo cp bmp_watchdog.service $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM

    

    echo "bmp_watchdog.service" | sudo tee -a $GENERATED_SERVICE_FILE
fi
if [ -f database.service ]; then
    sudo cp database.service $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM

    

    echo "database.service" | sudo tee -a $GENERATED_SERVICE_FILE
fi
if [ -f database@.service ]; then
    sudo cp database@.service $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM

    
    MULTI_INSTANCE="database@.service"
    SINGLE_INSTANCE=${MULTI_INSTANCE/"@"}
    sudo cp $SINGLE_INSTANCE $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM
    

    echo "database@.service" | sudo tee -a $GENERATED_SERVICE_FILE
fi
if [ -f database-chassis.service ]; then
    sudo cp database-chassis.service $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM

    

    echo "database-chassis.service" | sudo tee -a $GENERATED_SERVICE_FILE
fi
if [ -f bgp@.service ]; then
    sudo cp bgp@.service $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM

    
    MULTI_INSTANCE="bgp@.service"
    SINGLE_INSTANCE=${MULTI_INSTANCE/"@"}
    sudo cp $SINGLE_INSTANCE $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM
    

    echo "bgp@.service" | sudo tee -a $GENERATED_SERVICE_FILE
fi
if [ -f gnmi_watchdog.service ]; then
    sudo cp gnmi_watchdog.service $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM

    

    echo "gnmi_watchdog.service" | sudo tee -a $GENERATED_SERVICE_FILE
fi
if [ -f gnmi.service ]; then
    sudo cp gnmi.service $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM

    

    echo "gnmi.service" | sudo tee -a $GENERATED_SERVICE_FILE
fi
if [ -f lldp@.service ]; then
    sudo cp lldp@.service $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM

    
    MULTI_INSTANCE="lldp@.service"
    SINGLE_INSTANCE=${MULTI_INSTANCE/"@"}
    sudo cp $SINGLE_INSTANCE $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM
    

    echo "lldp@.service" | sudo tee -a $GENERATED_SERVICE_FILE
fi
if [ -f mux.service ]; then
    sudo cp mux.service $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM

    

    echo "mux.service" | sudo tee -a $GENERATED_SERVICE_FILE
fi
if [ -f swss@.service ]; then
    sudo cp swss@.service $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM

    
    MULTI_INSTANCE="swss@.service"
    SINGLE_INSTANCE=${MULTI_INSTANCE/"@"}
    sudo cp $SINGLE_INSTANCE $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM
    

    echo "swss@.service" | sudo tee -a $GENERATED_SERVICE_FILE
fi
if [ -f pmon.service ]; then
    sudo cp pmon.service $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM

    

    echo "pmon.service" | sudo tee -a $GENERATED_SERVICE_FILE
fi
if [ -f sflow.service ]; then
    sudo cp sflow.service $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM

    

    echo "sflow.service" | sudo tee -a $GENERATED_SERVICE_FILE
fi
if [ -f snmp.service ]; then
    sudo cp snmp.service $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM

    

    echo "snmp.service" | sudo tee -a $GENERATED_SERVICE_FILE
fi
if [ -f mgmt-framework.service ]; then
    sudo cp mgmt-framework.service $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM

    

    echo "mgmt-framework.service" | sudo tee -a $GENERATED_SERVICE_FILE
fi
if [ -f stp.service ]; then
    sudo cp stp.service $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM

    

    echo "stp.service" | sudo tee -a $GENERATED_SERVICE_FILE
fi
if [ -f sysmgr.service ]; then
    sudo cp sysmgr.service $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM

    

    echo "sysmgr.service" | sudo tee -a $GENERATED_SERVICE_FILE
fi
if [ -f teamd@.service ]; then
    sudo cp teamd@.service $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM

    
    MULTI_INSTANCE="teamd@.service"
    SINGLE_INSTANCE=${MULTI_INSTANCE/"@"}
    sudo cp $SINGLE_INSTANCE $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM
    

    echo "teamd@.service" | sudo tee -a $GENERATED_SERVICE_FILE
fi
if [ -f syncd@.service ]; then
    sudo cp syncd@.service $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM

    
    MULTI_INSTANCE="syncd@.service"
    SINGLE_INSTANCE=${MULTI_INSTANCE/"@"}
    sudo cp $SINGLE_INSTANCE $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM
    

    echo "syncd@.service" | sudo tee -a $GENERATED_SERVICE_FILE
fi
if [ -f gbsyncd@.service ]; then
    sudo cp gbsyncd@.service $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM

    
    MULTI_INSTANCE="gbsyncd@.service"
    SINGLE_INSTANCE=${MULTI_INSTANCE/"@"}
    sudo cp $SINGLE_INSTANCE $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM
    

    echo "gbsyncd@.service" | sudo tee -a $GENERATED_SERVICE_FILE
fi
if [ -f dash_engine.service ]; then
    sudo cp dash_engine.service $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM

    

    echo "dash_engine.service" | sudo tee -a $GENERATED_SERVICE_FILE
fi

if [ -f iccpd.service ]; then
    sudo LANG=C chroot $FILESYSTEM_ROOT systemctl disable iccpd.service
fi
sudo LANG=C chroot $FILESYSTEM_ROOT fuser -km /sys || true
sudo LANG=C chroot $FILESYSTEM_ROOT umount -lf /sys


# Copy service scripts (swss, syncd, bgp, teamd, lldp, radv)
sudo LANG=C cp $SCRIPTS_DIR/swss.sh $FILESYSTEM_ROOT/usr/local/bin/swss.sh
sudo LANG=C cp $SCRIPTS_DIR/syncd.sh $FILESYSTEM_ROOT/usr/local/bin/syncd.sh
sudo LANG=C cp $SCRIPTS_DIR/syncd_common.sh $FILESYSTEM_ROOT/usr/local/bin/syncd_common.sh
sudo LANG=C cp $SCRIPTS_DIR/gbsyncd.sh $FILESYSTEM_ROOT/usr/local/bin/gbsyncd.sh
sudo LANG=C cp $SCRIPTS_DIR/gbsyncd-platform.sh $FILESYSTEM_ROOT/usr/bin/gbsyncd-platform.sh
sudo LANG=C cp $SCRIPTS_DIR/bgp.sh $FILESYSTEM_ROOT/usr/local/bin/bgp.sh
sudo LANG=C cp $SCRIPTS_DIR/teamd.sh $FILESYSTEM_ROOT/usr/local/bin/teamd.sh
sudo LANG=C cp $SCRIPTS_DIR/lldp.sh $FILESYSTEM_ROOT/usr/local/bin/lldp.sh
sudo LANG=C cp $SCRIPTS_DIR/radv.sh $FILESYSTEM_ROOT/usr/local/bin/radv.sh
sudo LANG=C cp $SCRIPTS_DIR/database.sh $FILESYSTEM_ROOT/usr/local/bin/database.sh
sudo LANG=C cp $SCRIPTS_DIR/snmp.sh $FILESYSTEM_ROOT/usr/local/bin/snmp.sh
sudo LANG=C cp $SCRIPTS_DIR/telemetry.sh $FILESYSTEM_ROOT/usr/local/bin/telemetry.sh
sudo LANG=C cp $SCRIPTS_DIR/gnmi.sh $FILESYSTEM_ROOT/usr/local/bin/gnmi.sh
sudo LANG=C cp $SCRIPTS_DIR/bmp.sh $FILESYSTEM_ROOT/usr/local/bin/bmp.sh
sudo LANG=C cp $SCRIPTS_DIR/mgmt-framework.sh $FILESYSTEM_ROOT/usr/local/bin/mgmt-framework.sh
sudo LANG=C cp $SCRIPTS_DIR/asic_status.sh $FILESYSTEM_ROOT/usr/local/bin/asic_status.sh
sudo LANG=C cp $SCRIPTS_DIR/asic_status.py $FILESYSTEM_ROOT/usr/local/bin/asic_status.py
sudo LANG=C cp $SCRIPTS_DIR/startup_tsa_tsb.py $FILESYSTEM_ROOT/usr/local/bin/startup_tsa_tsb.py
sudo LANG=C cp $SCRIPTS_DIR/sonic-dpu-mgmt-traffic.sh $FILESYSTEM_ROOT/usr/local/bin/sonic-dpu-mgmt-traffic.sh
sudo LANG=C cp $SCRIPTS_DIR/dash-ha.sh $FILESYSTEM_ROOT/usr/local/bin/dash-ha.sh
# Copy sonic-netns-exec script
sudo LANG=C cp $SCRIPTS_DIR/sonic-netns-exec $FILESYSTEM_ROOT/usr/bin/sonic-netns-exec

# Copy write_standby script for mux state
sudo LANG=C cp $SCRIPTS_DIR/write_standby.py $FILESYSTEM_ROOT/usr/local/bin/write_standby.py

# Copy mark_dhcp_packet script
sudo LANG=C cp $SCRIPTS_DIR/mark_dhcp_packet.py $FILESYSTEM_ROOT/usr/local/bin/mark_dhcp_packet.py

sudo cp files/build_templates/startup_tsa_tsb.service $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM/

sudo cp $BUILD_TEMPLATES/sonic.target $FILESYSTEM_ROOT_USR_LIB_SYSTEMD_SYSTEM
sudo LANG=C chroot $FILESYSTEM_ROOT systemctl enable sonic.target

# All Python development packages must be removed, as they will conflict with the dependencies of the Python FIPS packages
sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-get purge -y python3-dev
sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-get purge -y libpython3-dev
sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-get purge -y '^python3\.[0-9]+-dev'
sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-get purge -y '^libpython3\.[0-9]+-dev'

sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-get purge -y libcairo2-dev libdbus-1-dev libgirepository1.0-dev libsystemd-dev pkg-config
sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-get clean -y
sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-get autoremove -y

sudo cp dockers/docker-database/base_image_files/redis-cli $FILESYSTEM_ROOT//usr/bin/redis-cli
sudo cp dockers/docker-fpm-frr/base_image_files/vtysh $FILESYSTEM_ROOT//usr/bin/vtysh
sudo cp dockers/docker-fpm-frr/base_image_files/rvtysh $FILESYSTEM_ROOT//usr/bin/rvtysh
sudo cp dockers/docker-fpm-frr/base_image_files/TSA $FILESYSTEM_ROOT//usr/bin/TSA
sudo cp dockers/docker-fpm-frr/base_image_files/TSB $FILESYSTEM_ROOT//usr/bin/TSB
sudo cp dockers/docker-fpm-frr/base_image_files/TSC $FILESYSTEM_ROOT//usr/bin/TSC
sudo cp dockers/docker-fpm-frr/base_image_files/TS $FILESYSTEM_ROOT//usr/bin/TS
sudo cp dockers/docker-fpm-frr/base_image_files/platform_utils $FILESYSTEM_ROOT//usr/bin/platform_utils
sudo cp dockers/docker-fpm-frr/base_image_files/idf_isolation $FILESYSTEM_ROOT//usr/bin/idf_isolation
sudo cp dockers/docker-fpm-frr/base_image_files/prefix_list $FILESYSTEM_ROOT//usr/bin/prefix_list
sudo cp dockers/docker-sonic-gnmi/base_image_files/monit_gnmi $FILESYSTEM_ROOT//etc/monit/conf.d
sudo cp dockers/docker-lldp/base_image_files/lldpctl $FILESYSTEM_ROOT//usr/bin/lldpctl
sudo cp dockers/docker-lldp/base_image_files/lldpcli $FILESYSTEM_ROOT//usr/bin/lldpcli
sudo cp dockers/docker-orchagent/base_image_files/swssloglevel $FILESYSTEM_ROOT//usr/bin/swssloglevel
sudo cp dockers/docker-platform-monitor/base_image_files/cmd_wrapper $FILESYSTEM_ROOT//usr/bin/sensors
sudo cp dockers/docker-platform-monitor/base_image_files/cmd_wrapper $FILESYSTEM_ROOT//usr/sbin/iSmart
sudo cp dockers/docker-platform-monitor/base_image_files/cmd_wrapper $FILESYSTEM_ROOT//usr/sbin/SmartCmd
sudo cp dockers/docker-sflow/base_image_files/psample $FILESYSTEM_ROOT//usr/bin/psample
sudo cp dockers/docker-sflow/base_image_files/sflowtool $FILESYSTEM_ROOT//usr/bin/sflowtool
sudo cp dockers/docker-snmp/base_image_files/monit_snmp $FILESYSTEM_ROOT//etc/monit/conf.d
sudo cp dockers/docker-sonic-mgmt-framework/base_image_files/sonic-cli $FILESYSTEM_ROOT//usr/bin/eguard-cli
sudo cp dockers/docker-stp/base_image_files/stpctl $FILESYSTEM_ROOT//usr/bin/stpctl
sudo cp dockers/docker-teamd/base_image_files/teamdctl $FILESYSTEM_ROOT//usr/bin/teamdctl



sudo mkdir $FILESYSTEM_ROOT/etc/sonic/frr
sudo touch $FILESYSTEM_ROOT/etc/sonic/frr/frr.conf
sudo touch $FILESYSTEM_ROOT/etc/sonic/frr/vtysh.conf
sudo chown -R $FRR_USER_UID:$FRR_USER_GID $FILESYSTEM_ROOT/etc/sonic/frr
sudo chmod -R 640 $FILESYSTEM_ROOT/etc/sonic/frr/
sudo chmod 750 $FILESYSTEM_ROOT/etc/sonic/frr

# Mask services which are disabled by default
sudo cp $BUILD_SCRIPTS_DIR/mask_disabled_services.py $FILESYSTEM_ROOT/tmp/
sudo chmod a+x $FILESYSTEM_ROOT/tmp/mask_disabled_services.py
sudo LANG=C chroot $FILESYSTEM_ROOT /tmp/mask_disabled_services.py
sudo rm -rf $FILESYSTEM_ROOT/tmp/mask_disabled_services.py


sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-get -y install python3-dbus

# Install FIPS python package will break apt-get purge command, so install after all purge command finish 
if [ "$INCLUDE_FIPS" == y ]; then
    install_deb_package target/debs/bookworm/libpython3.11-minimal_3.11.2-6+fips_amd64.deb
    install_deb_package target/debs/bookworm/libpython3.11-stdlib_3.11.2-6+fips_amd64.deb
    install_deb_package target/debs/bookworm/libpython3.11_3.11.2-6+fips_amd64.deb
    install_deb_package target/debs/bookworm/python3.11-minimal_3.11.2-6+fips_amd64.deb
    install_deb_package target/debs/bookworm/python3.11_3.11.2-6+fips_amd64.deb
    
    
fi


## Unhold installed packages to allow these packages be upgrade after SONiC installed
PACKAGE_NAME=$(dpkg-deb -f target/debs/bookworm/systemd-sonic-generator_1.0.0_amd64.deb Package)
sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-mark unhold $PACKAGE_NAME
## Unhold installed packages to allow these packages be upgrade after SONiC installed
PACKAGE_NAME=$(dpkg-deb -f target/debs/bookworm/libssl3_3.0.11-1~deb12u2+fips_amd64.deb Package)
sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-mark unhold $PACKAGE_NAME
## Unhold installed packages to allow these packages be upgrade after SONiC installed
PACKAGE_NAME=$(dpkg-deb -f target/debs/bookworm/libssl-dev_3.0.11-1~deb12u2+fips_amd64.deb Package)
sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-mark unhold $PACKAGE_NAME
## Unhold installed packages to allow these packages be upgrade after SONiC installed
PACKAGE_NAME=$(dpkg-deb -f target/debs/bookworm/openssl_3.0.11-1~deb12u2+fips_amd64.deb Package)
sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-mark unhold $PACKAGE_NAME
## Unhold installed packages to allow these packages be upgrade after SONiC installed
PACKAGE_NAME=$(dpkg-deb -f target/debs/bookworm/symcrypt-openssl_1.5.2_amd64.deb Package)
sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-mark unhold $PACKAGE_NAME
## Unhold installed packages to allow these packages be upgrade after SONiC installed
PACKAGE_NAME=$(dpkg-deb -f target/debs/bookworm/openssh-client_9.2p1-2+deb12u5+fips_amd64.deb Package)
sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-mark unhold $PACKAGE_NAME
## Unhold installed packages to allow these packages be upgrade after SONiC installed
PACKAGE_NAME=$(dpkg-deb -f target/debs/bookworm/ssh_9.2p1-2+deb12u5+fips_all.deb Package)
sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-mark unhold $PACKAGE_NAME
## Unhold installed packages to allow these packages be upgrade after SONiC installed
PACKAGE_NAME=$(dpkg-deb -f target/debs/bookworm/openssh-sftp-server_9.2p1-2+deb12u5+fips_amd64.deb Package)
sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-mark unhold $PACKAGE_NAME
## Unhold installed packages to allow these packages be upgrade after SONiC installed
PACKAGE_NAME=$(dpkg-deb -f target/debs/bookworm/openssh-server_9.2p1-2+deb12u5+fips_amd64.deb Package)
sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-mark unhold $PACKAGE_NAME
## Unhold installed packages to allow these packages be upgrade after SONiC installed
PACKAGE_NAME=$(dpkg-deb -f target/debs/bookworm/libk5crypto3_1.20.1-2+deb12u1+fips_amd64.deb Package)
sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-mark unhold $PACKAGE_NAME



## Enable MULTIDB


# Install syslog counter plugin
install_deb_package $debs_path/syslog-counter_*.deb
