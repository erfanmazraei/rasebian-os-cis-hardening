#!/bin/bash

set -x 

#CiS debian Linux 10 benchmark
#v1.0.0 - 02-13-202

export HOME_DIR="/home/naad"
export ROOT_PASSWORD="naad"

main() {
    pre_exec
    1_initial_setup
    2_services
    3_network_configuration
    4_logging_and_auditing
    5_access_and_authentication_and_authorization
    6_System_maintenance
}

pre_exec() {
    apt update
    mkdir -p $HOME_DIR
}

1_initial_setup(){
    1_1_file_system_configuration
    1_2_configure_software_updates
    1_3_configure_sudo
    1_4_filesystem_integrity_checking
    1_5_secure_boot_settings
    1_6_additional_process_hardening
    1_7_mandatory_access_control
    1_8_warning_banners
    1_9_ensure_updates_and_patches_and_additional_security_software_are_installed_not_scored
}

1_1_file_system_configuration() {
    1_1_1_disable_unused_filesystems
    1_1_2_ensure_tmp_is_configured_scored
    1_1_3_ensure_nodev_option_set_on_tmp_partition_scored
    1_1_4_ensure_nosuid_option_set_on_tmp_partition_scored
    1_1_5_ensure_noexec_option_set_on_tmp_partition_scored
    1_1_6_ensure_separate_partition_exists_for_var_scored
    1_1_7_ensure_separate_partition_exists_for_var_tmp_scored
    1_1_8_ensure_nodev_option_set_on_var_tmp_partition_scored
    1_1_9_ensure_nosuid_option_set_on_var_tmp_partition_scored
    1_1_10_ensure_noexec_option_set_on_var_tmp_partition_scored
    1_1_11_ensure_separate_partition_exists_for_var_log_scored
    1_1_12_ensure_separate_partition_exists_for_var_log_audit_scored
    1_1_13_ensure_separate_partition_exists_for_home_scored
    1_1_14_ensure_nodev_option_set_on_home_partition_scored
    1_1_15_ensure_nodev_option_set_on_dev_shm_partition_scored
    1_1_16_ensure_nosuid_option_set_on_dev_shm_partition_scored
    1_1_17_ensure_noexec_option_set_on_dev_shm_partition_scored
    1_1_18_ensure_nodev_option_set_on_removable_media_partitions_not_scored
    1_1_19_ensure_nosuid_option_set_on_removable_media_partitions_not_scored
    1_1_20_ensure_noexec_option_set_on_removable_media_partitions_not_scored
    1_1_21_ensure_sticky_bit_is_set_on_all_world_writable_directories_scored
    1_1_22_disable_automounting_scored
    1_1_23_disable_usb_storage_scored
}

1_1_1_disable_unused_filesystems() {
    1_1_1_1_ensure_mounting_of_freevxfs_filesystems_is_disabled_scored
    1_1_1_2_ensure_mounting_of_jffs2_filesystems_is_disabled_scored
    1_1_1_3_ensure_mounting_of_hfs_filesystems_is_disabled_scored
    1_1_1_4_ensure_mounting_of_hfsplus_filesystems_is_disabled_scored
    1_1_1_5_ensure_mounting_of_squashfs_filesystems_is_disabled_scored
    1_1_1_6_ensure_mounting_of_udf_filesystem_is_disabled_scored
    1_1_1_7_ensure_mounting_of_fat_filesystems_is_limited_not_scored
    
}

1_1_1_1_ensure_mounting_of_freevxfs_filesystems_is_disabled_scored() {
    echo "install freevxfs /bin/true" > /etc/modprobe.d/freevxfs.conf
    rmmod freevxfs
}

1_1_1_2_ensure_mounting_of_jffs2_filesystems_is_disabled_scored() {
    echo "install jffs2 /bin/true" > /etc/modprobe.d/jffs2.conf
    rmmod jffs2
}

1_1_1_3_ensure_mounting_of_hfs_filesystems_is_disabled_scored() {
    echo "install hfs /bin/true" > /etc/modprobe.d/hfs.conf
    rmmod hfs
}

1_1_1_4_ensure_mounting_of_hfsplus_filesystems_is_disabled_scored() {
    echo "install hfsplus /bin/true" > /etc/modprobe.d/hfsplus.conf
    rmmod hfsplus
}

1_1_1_5_ensure_mounting_of_squashfs_filesystems_is_disabled_scored() {
    echo "install squashfs /bin/true" > /etc/modprobe.d/squashfs.conf
    rmmod squashfs
}

1_1_1_6_ensure_mounting_of_udf_filesystem_is_disabled_scored() {
    echo "install udf /bin/true" > /etc/modprobe.d/udf.conf
    rmmod udf
}

1_1_1_7_ensure_mounting_of_fat_filesystems_is_limited_not_scored() {
    echo "install vfat /bin/true" > /etc/modprobe.d/vfat.conf
    rmmod vfat
}

1_1_2_ensure_tmp_is_configured_scored() {
    pass
}

1_1_3_ensure_nodev_option_set_on_tmp_partition_scored() {
    pass
}

1_1_4_ensure_nosuid_option_set_on_tmp_partition_scored() {
    pass
}

1_1_5_ensure_noexec_option_set_on_tmp_partition_scored() {
    pass
}

1_1_6_ensure_separate_partition_exists_for_var_scored() {
    pass
}

1_1_7_ensure_separate_partition_exists_for_var_tmp_scored() {
    pass
}

1_1_8_ensure_nodev_option_set_on_var_tmp_partition_scored() {
    pass
}

1_1_9_ensure_nosuid_option_set_on_var_tmp_partition_scored() {
    pass
}

1_1_10_ensure_noexec_option_set_on_var_tmp_partition_scored() {
    pass
}

1_1_11_ensure_separate_partition_exists_for_var_log_scored() {
    pass
}

1_1_12_ensure_separate_partition_exists_for_var_log_audit_scored() {
    pass
}

1_1_13_ensure_separate_partition_exists_for_home_scored() {
    pass
}

1_1_14_ensure_nodev_option_set_on_home_partition_scored() {
    pass
}

1_1_15_ensure_nodev_option_set_on_dev_shm_partition_scored() {
    pass
}

1_1_16_ensure_nosuid_option_set_on_dev_shm_partition_scored(){
    pass
}

1_1_17_ensure_noexec_option_set_on_dev_shm_partition_scored(){
    pass
}

1_1_18_ensure_nodev_option_set_on_removable_media_partitions_not_scored() {
    pass
}

1_1_19_ensure_nosuid_option_set_on_removable_media_partitions_not_scored() {
    pass
}

1_1_20_ensure_noexec_option_set_on_removable_media_partitions_not_scored() {
    pass
}

1_1_21_ensure_sticky_bit_is_set_on_all_world_writable_directories_scored() {
    df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev \
    -type d \( -perm -0002 -a ! -perm -1000 \) \
    2>/dev/null > sticky_bit_is_set_on_all_world_writable_directories_list.txt
    while read p; do
        chmod a+t "$p"
    done <sticky_bit_is_set_on_all_world_writable_directories_list.txt
    rm -f sticky_bit_is_set_on_all_world_writable_directories_list.txt
}

1_1_22_disable_automounting_scored() {
    systemctl --now disable autofs
    apt purge autofs
}

1_1_23_disable_usb_storage_scored() {
    echo "install usb-storage /bin/true" > /etc/modprobe.d/usb_storage.conf
    rmmod usb-storage
}

1_2_configure_software_updates() {
    1_2_1_ensure_package_manager_repositories_are_configured_not_scored
    1_2_2_ensure_gpg_keys_are_configured_not_scored
}

1_2_1_ensure_package_manager_repositories_are_configured_not_scored() {
    pass
}

1_2_2_ensure_gpg_keys_are_configured_not_scored() {
    pass
}

1_3_configure_sudo() {
    1_3_1_ensure_sudo_is_installed_scored
    1_3_2_ensure_sudo_commands_use_pty_scored
    1_3_3_ensure_sudo_log_file_exists_scored
}

1_3_1_ensure_sudo_is_installed_scored() {
    apt install sudo -y
}

1_3_2_ensure_sudo_commands_use_pty_scored() {
    echo "Defaults   use_pty" >> /etc/sudoers
}

1_3_3_ensure_sudo_log_file_exists_scored() {
    echo "Defaults  logfile="$HOME_DIR/sudo_log.txt"" >> /etc/sudoers
}

1_4_filesystem_integrity_checking() {
    1_4_1_ensure_aide_is_installed_scored
    1_4_2_ensure_filesystem_integrity_is_regularly_checked_scored
}

1_4_1_ensure_aide_is_installed_scored() {
    pass
}

1_4_2_ensure_filesystem_integrity_is_regularly_checked_scored() {
    pass
}

1_5_secure_boot_settings() {
    1_5_1_ensure_permissions_on_bootloader_config_are_configured_scored
    1_5_2_ensure_bootloader_password_is_set_scored
    1_5_3_ensure_authentication_required_for_single_user_mode_scored
}

1_5_1_ensure_permissions_on_bootloader_config_are_configured_scored() {
    pass
}

1_5_2_ensure_bootloader_password_is_set_scored() {
    pass
}

1_5_3_ensure_authentication_required_for_single_user_mode_scored() {
    echo "root:$(echo "$ROOT_PASSWORD")" | chpasswd
}

1_6_additional_process_hardening() {
    1_6_1_ensure_xd_nx_support_is_enabled_scored
    1_6_2_ensure_address_space_layout_randomization_aslr_is_enabled_scored
    1_6_3_ensure_prelink_is_disabled_scored
    1_6_4_ensure_core_dumps_are_restricted_scored
}

1_6_1_ensure_xd_nx_support_is_enabled_scored() {
    pass
}

1_6_2_ensure_address_space_layout_randomization_aslr_is_enabled_scored() {
    pass
}

1_6_3_ensure_prelink_is_disabled_scored() {
    pass
}

1_6_4_ensure_core_dumps_are_restricted_scored() {
    pass
}


1_7_mandatory_access_control() {
    1_7_1_configure_apparmor
}

1_7_1_configure_apparmor() {
    1_7_1_1_ensure_apparmor_is_installed_scored
    1_7_1_2_ensure_apparmor_is_enabled_in_the_bootloader_configuration_scored
    1_7_1_3_ensure_all_apparmor_profiles_are_in_enforce_or_complain_mode_scored
    1_7_1_4_ensure_all_apparmor_profiles_are_enforcing_scored

}

1_7_1_1_ensure_apparmor_is_installed_scored() {
    pass
}

1_7_1_2_ensure_apparmor_is_enabled_in_the_bootloader_configuration_scored() {
    pass
}

1_7_1_3_ensure_all_apparmor_profiles_are_in_enforce_or_complain_mode_scored() {
    pass
}

1_7_1_4_ensure_all_apparmor_profiles_are_enforcing_scored() {
    pass
}

1_8_warning_banners() {
    1_8_1_command_line_warning_banners
    1_8_2_ensur_gdm_login_banner_is_configured_scored
}

1_8_1_command_line_warning_banners() {
    1_8_1_1_ensure_message_of_the_day_is_configured_properly_scored
    1_8_1_2_ensure_local_login_warning_banner_is_configured_properly_scored
    1_8_1_3_ensure_remote_login_warning_banner_is_configured_properly_scored
    1_8_1_4_ensure_permissions_on_etc_motd_are_configured_scored
    1_8_1_5_ensure_permissions_on_etc_issue_are_configured_scored
    1_8_1_6_ensure_permissions_on_etc_issue_net_are_configured_scored
}

1_8_1_1_ensure_message_of_the_day_is_configured_properly_scored() {
    rm /etc/motd
}

1_8_1_2_ensure_local_login_warning_banner_is_configured_properly_scored() {
    echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue
}

1_8_1_3_ensure_remote_login_warning_banner_is_configured_properly_scored() {
    echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net
}

1_8_1_4_ensure_permissions_on_etc_motd_are_configured_scored() {
    chown root:root /etc/motd
    chmod u-x,go-wx /etc/motd
}

1_8_1_5_ensure_permissions_on_etc_issue_are_configured_scored() {
    chown root:root /etc/issue
    chmod u-x,go-wx /etc/issue
}

1_8_1_6_ensure_permissions_on_etc_issue_net_are_configured_scored() {
    chown root:root /etc/issue.net
    chmod u-x,go-wx /etc/issue.net
}

1_8_2_ensur_gdm_login_banner_is_configured_scored() {
    pass
}

1_9_ensure_updates_and_patches_and_additional_security_software_are_installed_not_scored() {
    pass
}

2_services() {
    2_1_inetd_services
    2_2_special_purpose_services
    2_3_service_clients
}

2_1_inetd_services() {
    2_1_1_ensure_xinetd_is_not_installed_scored
    2_1_2_ensure_openbsd_inetd_is_not_installed_scored

}

2_1_1_ensure_xinetd_is_not_installed_scored() {
    apt purge xinetd -y
}

2_1_2_ensure_openbsd_inetd_is_not_installed_scored() {
    apt purge openbsd-inetd -y 
}

2_2_special_purpose_services() {
    2_2_1_time_synchronization
    2_2_2_ensure_x_window_system_is_not_installed_scored
    2_2_3_ensure_avahi_server_is_not_enabled_scored
    2_2_4_ensure_cups_is_not_enabled_scored
    2_2_5_ensure_dhcp_server_is_not_enabled_scored
    2_2_6_ensure_ldap_server_is_not_enabled_scored
    2_2_7_ensure_nfs_and_rpc_are_not_enabled_scored
    2_2_8_ensure_dns_server_is_not_enabled_scored
    2_2_9_ensure_ftp_server_is_not_enabled_scored
    2_2_10_ensure_http_server_is_not_enabled_scored
    2_2_11_ensure_email_services_are_not_enabled_scored
    2_2_12_ensure_samba_is_not_enabled_scored
    2_2_13_ensure_http_proxy_server_is_not_enabled_scored
    2_2_14_ensure_snmp_server_is_not_enabled_scored
    2_2_15_ensure_mail_transfer_agent_is_configured_for_local_only_mode_scored
    2_2_16_ensure_rsync_service_is_not_enabled_scored
    2_2_17_ensure_nis_server_is_not_enabled_scored

}

2_2_1_time_synchronization() {
    2_2_1_1_ensure_time_synchronization_is_in_use_scored
    2_2_1_2_ensure_systemd_timesyncd_is_configured_not_scored
    2_2_1_3_ensure_chrony_is_configured_scored
    2_2_1_4_ensure_ntp_is_configured_scored
}

2_2_1_1_ensure_time_synchronization_is_in_use_scored() {
    apt install ntp -y
}

2_2_1_2_ensure_systemd_timesyncd_is_configured_not_scored() {
    echo "not scored"
}

2_2_1_3_ensure_chrony_is_configured_scored() {
    echo "we use ntp"
}

2_2_1_4_ensure_ntp_is_configured_scored() {
    echo "we do this in 2_1_1_1"
}

2_2_2_ensure_x_window_system_is_not_installed_scored() {
    apt purge xserver-xorg* -y
}

2_2_3_ensure_avahi_server_is_not_enabled_scored() {
    systemctl --now disable avahi-daemon
}

2_2_4_ensure_cups_is_not_enabled_scored() {
    systemctl --now disable cups
}

2_2_5_ensure_dhcp_server_is_not_enabled_scored() {
    echo "we need dhcp server"
}

2_2_6_ensure_ldap_server_is_not_enabled_scored() {
    systemctl --now disable slapd
}

2_2_7_ensure_nfs_and_rpc_are_not_enabled_scored() {
    systemctl --now disable nfs-server
    systemctl --now disable rpcbind
}

2_2_8_ensure_dns_server_is_not_enabled_scored() {
    systemctl --now disable bind9
}

2_2_9_ensure_ftp_server_is_not_enabled_scored() {
    systemctl --now disable vsftpd
}

2_2_10_ensure_http_server_is_not_enabled_scored() {
    echo "we need http server"
}

2_2_11_ensure_email_services_are_not_enabled_scored() {
    systemctl --now disable dovecot
}

2_2_12_ensure_samba_is_not_enabled_scored() {
    systemctl --now disable smbd
}

2_2_13_ensure_http_proxy_server_is_not_enabled_scored() {
    systemctl --now disable squid
}

2_2_14_ensure_snmp_server_is_not_enabled_scored() {
    systemctl --now disable snmpd
}

2_2_15_ensure_mail_transfer_agent_is_configured_for_local_only_mode_scored() {
    echo "badan"
}

2_2_16_ensure_rsync_service_is_not_enabled_scored() {
    systemctl --now disable rsync
}

2_2_17_ensure_nis_server_is_not_enabled_scored() {
    systemctl --now disable nis
}


2_3_service_clients() {
    2_3_1_ensure_nis_client_is_not_installed_scored
    2_3_2_ensure_rsh_client_is_not_installed_scored
    2_3_3_ensure_talk_client_is_not_installed_scored
    2_3_4_ensure_telnet_client_is_not_installed_scored
    2_3_5_ensure_ldap_client_is_not_installed_scored

}

2_3_1_ensure_nis_client_is_not_installed_scored() {
    apt purge nis -y
}

2_3_2_ensure_rsh_client_is_not_installed_scored() {
    apt purge rsh-client -y
}

2_3_3_ensure_talk_client_is_not_installed_scored() {
    apt purge talk -y
}

2_3_4_ensure_telnet_client_is_not_installed_scored() {
    apt purge telnet -y
}

2_3_5_ensure_ldap_client_is_not_installed_scored() {
    apt purge ldap-utils -y
}

3_Network_configuration() {
    3_1_disable_unused_network_protocols_and_devices
    3_2_network_parameters_host_only
    3_3_network_parameters_host_and_router
    3_4_uncommon_network_protocols
    3_5_firewall_configuration
}

3_1_disable_unused_network_protocols_and_devices() {
    3_1_1_disable_ipv6_not_scored
    3_1_2_ensure_wireless_interfaces_are_disabled_scored

}

3_1_1_disable_ipv6_not_scored() {
    sed -i 's/GRUB_CMDLINE_LINUX="/&ipv6.disable=1 /' /etc/default/grub
    update-grub
}

3_1_2_ensure_wireless_interfaces_are_disabled_scored() {
    nmcli radio all off
}

3_2_network_parameters_host_only() {
    3_2_1_ensure_packet_redirect_sending_is_disabled_scored
    3_2_2_ensure_ip_forwarding_is_disabled_scored
}

3_2_1_ensure_packet_redirect_sending_is_disabled_scored() {
    find /etc/sysctl.d/* -type f -exec sed -i '/net.ipv4.conf.all.send_redirects/d' '{}' \;
    find /etc/sysctl.d/* -type f -exec sed -i '/net.ipv4.conf.default.send_redirects/d' '{}' \;
    sed -i '/net.ipv4.conf.all.send_redirects/d' /etc/sysctl.conf
    sed -i '/net.ipv4.conf.default.send_redirects/d' /etc/sysctl.conf
    echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
    echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
    sysctl -w net.ipv4.conf.all.send_redirects=0
    sysctl -w net.ipv4.conf.default.send_redirects=0
    sysctl -w net.ipv4.route.flush=1
}

3_2_2_ensure_ip_forwarding_is_disabled_scored() {
    grep -Els "^\s*net\.ipv4\.ip_forward\s*=\s*1" /etc/sysctl.conf \
    /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf | while \
    read filename; do sed -ri "s/^\s*(net\.ipv4\.ip_forward\s*)(=)(\s*\S+\b).*$/# \
    *REMOVED* \1/" $filename; done; sysctl -w net.ipv4.ip_forward=0; sysctl -w \
    net.ipv4.route.flush=1
}

3_3_network_parameters_host_and_router() {
    3_3_1_ensure_source_routed_packets_are_not_accepted_scored
    3_3_2_ensure_icmp_redirects_are_not_accepted_scored
    3_3_3_ensure_secure_icmp_redirects_are_not_accepted_scored
    3_3_4_ensure_suspicious_packets_are_logged_scored
    3_3_5_ensure_broadcast_icmp_requests_are_ignored_scored
    3_3_6_ensure_bogus_icmp_responses_are_ignored_scored
    3_3_7_ensure_reverse_path_filtering_is_enabled_scored
    3_3_8_ensure_tcp_syn_cookies_is_enabled_scored
    3_3_9_ensure_ipv6_router_advertisements_are_not_accepted_scored

}

3_3_1_ensure_source_routed_packets_are_not_accepted_scored() {
    find /etc/sysctl.d/* -type f -exec sed -i '/net.ipv4.conf.all.accept_source_route/d' '{}' \;
    find /etc/sysctl.d/* -type f -exec sed -i '/net.ipv4.conf.default.accept_source_route/d' '{}' \;
    sed -i '/net.ipv4.conf.all.accept_source_route/d' /etc/sysctl.conf
    sed -i '/net.ipv4.conf.default.accept_source_route/d' /etc/sysctl.conf
    echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
    echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
    sysctl -w net.ipv4.conf.all.accept_source_route=0
    sysctl -w net.ipv4.conf.default.accept_source_route=0
    sysctl -w net.ipv4.route.flush=1
}

3_3_2_ensure_icmp_redirects_are_not_accepted_scored() {
    find /etc/sysctl.d/* -type f -exec sed -i '/net.ipv4.conf.all.accept_redirects/d' '{}' \;
    find /etc/sysctl.d/* -type f -exec sed -i '/net.ipv4.conf.default.accept_redirects/d' '{}' \;
    sed -i '/net.ipv4.conf.all.accept_redirects/d' /etc/sysctl.conf
    sed -i '/net.ipv4.conf.default.accept_redirects/d' /etc/sysctl.conf
    echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
    echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
    sysctl -w net.ipv4.conf.all.accept_redirects=0
    sysctl -w net.ipv4.conf.default.accept_redirects=0
    sysctl -w net.ipv4.route.flush=1
}

3_3_3_ensure_secure_icmp_redirects_are_not_accepted_scored(){
    find /etc/sysctl.d/* -type f -exec sed -i '/net.ipv4.conf.all.secure_redirects/d' '{}' \;
    find /etc/sysctl.d/* -type f -exec sed -i '/net.ipv4.conf.default.secure_redirects/d' '{}' \;
    sed -i '/net.ipv4.conf.all.secure_redirects/d' /etc/sysctl.conf
    sed -i '/net.ipv4.conf.default.secure_redirects/d' /etc/sysctl.conf
    echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
    echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf
    sysctl -w net.ipv4.conf.all.secure_redirects=0
    sysctl -w net.ipv4.conf.default.secure_redirects=0
    sysctl -w net.ipv4.route.flush=1
}

3_3_4_ensure_suspicious_packets_are_logged_scored() {
    #maybe disk not free for log
#    find /etc/sysctl.d/* -type f -exec sed -i '/net.ipv4.conf.all.log_martians/d' '{}' \;
#    find /etc/sysctl.d/* -type f -exec sed -i '/net.ipv4.conf.default.log_martians/d' '{}' \;
#    sed -i '/net.ipv4.conf.all.log_martians/d' /etc/sysctl.conf
#    sed -i '/net.ipv4.conf.default.log_martians/d' /etc/sysctl.conf
#    echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
#    echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.conf
}

3_3_5_ensure_broadcast_icmp_requests_are_ignored_scored() {
    find /etc/sysctl.d/* -type f -exec sed -i '/net.ipv4.icmp_echo_ignore_broadcasts/d' '{}' \;
    sed -i '/net.ipv4.icmp_echo_ignore_broadcasts/d' /etc/sysctl.conf
    echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
    sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
    sysctl -w net.ipv4.route.flush=1
}
3_3_6_ensure_bogus_icmp_responses_are_ignored_scored() {
    find /etc/sysctl.d/* -type f -exec sed -i '/net.ipv4.icmp_ignore_bogus_error_responses/d' '{}' \;
    sed -i '/net.ipv4.icmp_ignore_bogus_error_responses/d' /etc/sysctl.conf
    echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf
}

3_3_7_ensure_reverse_path_filtering_is_enabled_scored() {
    find /etc/sysctl.d/* -type f -exec sed -i '/net.ipv4.conf.all.rp_filter/d' '{}' \;
    find /etc/sysctl.d/* -type f -exec sed -i '/net.ipv4.conf.default.rp_filter/d' '{}' \;
    sed -i '/net.ipv4.conf.all.rp_filter/d' /etc/sysctl.conf
    sed -i '/net.ipv4.conf.default.rp_filter/d' /etc/sysctl.conf
    echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
    echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf
    sysctl -w net.ipv4.conf.all.rp_filter=1
    sysctl -w net.ipv4.conf.default.rp_filter=1
    sysctl -w net.ipv4.route.flush=1
}

3_3_8_ensure_tcp_syn_cookies_is_enabled_scored() {
    
    find /etc/sysctl.d/* -type f -exec sed -i '/net.ipv4.tcp_syncookies/d' '{}' \;
    sed -i '/net.ipv4.tcp_syncookies/d' /etc/sysctl.conf
    echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
    sysctl -w net.ipv4.tcp_syncookies=1
    sysctl -w net.ipv4.route.flush=1
}

3_3_9_ensure_ipv6_router_advertisements_are_not_accepted_scored() {
    echo "ipv6 is disable"
}

3_4_uncommon_network_protocols() {
    3_4_1_ensure_dccp_is_disabled_scored
    3_4_2_ensure_sctp_is_disabled_scored
    3_4_3_ensure_rds_is_disabled_scored
    3_4_4_ensure_tips_is_disabled_scored
}

3_4_1_ensure_dccp_is_disabled_scored() {
    echo "install dccp /bin/true" >> /etc/modprobe.d/dccp.conf
}

3_4_2_ensure_sctp_is_disabled_scored() {
    echo "install sctp /bin/true" >> /etc/modprobe.d/sctp.conf
}

3_4_3_ensure_rds_is_disabled_scored() {
    echo "install rds /bin/true" >> /etc/modprobe.d/rds.conf
}

3_4_4_ensure_tips_is_disabled_scored() {
    echo "install tipc /bin/true" >> /etc/modprobe.d/tipc.conf
}

3_5_firewall_configuration() {
    3_5_1_ensure_firewall_software_is_installed
    3_5_2_configure_uncomplicatedfirewall
    3_5_3_configure_nftables
    3_5_4_configure_iptables

}

3_5_1_ensure_firewall_software_is_installed() {
    3_5_1_1_ensure_a_firewall_package_is_installed_scored
}

3_5_1_1_ensure_a_firewall_package_is_installed_scored() {
    pass
}

3_5_2_configure_uncomplicatedfirewall() {
    3_5_2_1_ensure_ufw_service_is_enabled_scored
    3_5_2_2_ensure_default_deny_firewall_policy_scored
    3_5_2_3_ensure_loopback_traffic_is_configured_scored
    3_5_2_4_ensure_outbound_connections_are_configured_not_scored
    3_5_2_5_ensure_firewall_rules_exist_for_all_open_ports_scored
    
}

3_5_2_1_ensure_ufw_service_is_enabled_scored() {
    pass
}

3_5_2_2_ensure_default_deny_firewall_policy_scored() {
    pass
}

3_5_2_3_ensure_loopback_traffic_is_configured_scored() {
    pass
}

3_5_2_4_ensure_outbound_connections_are_configured_not_scored() {
    pass
}

3_5_2_5_ensure_firewall_rules_exist_for_all_open_ports_scored() {
    pass
}

3_5_3_configure_nftables() {
    3_5_3_1_ensure_iptables_are_flushed_not_scored
    3_5_3_2_ensure_a_table_exists_scored
    3_5_3_3_ensure_base_chains_exist_scored
    3_5_3_4_ensure_loopback_traffic_is_configured_scored
    3_5_3_5_ensure_outbound_and_established_connections_are_configured_not_scored
    3_5_3_6_ensure_default_deny_firewall_policy_scored
    3_5_3_7_ensure_nftables_service_is_enabled_scored
    3_5_3_8_ensure_nftables_rules_are_permanent_scored

}

3_5_3_1_ensure_iptables_are_flushed_not_scored() {
    pass
}

3_5_3_2_ensure_a_table_exists_scored() {
    pass
}

3_5_3_3_ensure_base_chains_exist_scored() {
    pass
}

3_5_3_4_ensure_loopback_traffic_is_configured_scored() {
    pass
}

3_5_3_5_ensure_outbound_and_established_connections_are_configured_not_scored() {
    pass
}

3_5_3_6_ensure_default_deny_firewall_policy_scored() {
    pass
}

3_5_3_7_ensure_nftables_service_is_enabled_scored() {
    pass
}

3_5_3_8_ensure_nftables_rules_are_permanent_scored() {
    pass
}

3_5_4_configure_iptables() {
    3_5_4_1_1_ensure_default_deny_firewall_policy_scored
    3_5_4_1_2_ensure_loopback_traffic_is_configured_scored
    3_5_4_1_3_ensure_outbound_and_established_connections_are_configured_not_scored
    3_5_4_1_4_ensure_firewall_rules_exist_for_all_open_ports_scored
    3_5_4_2_1_ensure_IPv6_default_deny_firewall_policy_scored
    3_5_4_2_2_ensure_IPv6_loopback_traffic_is_configured_scored
    3_5_4_2_3_ensure_IPv6_outbound_and_established_connections_are_configured_not_scored
    3_5_4_2_4_ensure_IPv6_firewall_rules_exist_for_all_open_ports_not_scored
}

3_5_4_1_1_ensure_default_deny_firewall_policy_scored() {
    pass
}

3_5_4_1_2_ensure_loopback_traffic_is_configured_scored() {
    pass
}

3_5_4_1_3_ensure_outbound_and_established_connections_are_configured_not_scored() {
    pass
}

3_5_4_1_4_ensure_firewall_rules_exist_for_all_open_ports_scored() {
    pass
}

3_5_4_2_1_ensure_IPv6_default_deny_firewall_policy_scored() {
    pass
}

3_5_4_2_2_ensure_IPv6_loopback_traffic_is_configured_scored() {
    pass
}

3_5_4_2_3_ensure_IPv6_outbound_and_established_connections_are_configured_not_scored() {
    pass
}

3_5_4_2_4_ensure_IPv6_firewall_rules_exist_for_all_open_ports_not_scored() {
    pass
}

4_logging_and_auditing() {
    4_1_configure_system_accounting
    4_2_configure_logging
}

4_1_configure_system_accounting() {
    4_1_1_ensure_auditing_is_enabled
    4_1_2_configure_data_retention
    4_1_3_ensure_events_that_modify_date_and_time_information_are_collected_scored
    4_1_4_ensure_events_that_modify_user_group_information_are_collected_scored
    4_1_5_ensure_events_that_modify_the_systems_network_environment_are_collected_scored
    4_1_6_ensure_events_that_modify_the_systems_mandatory_access_controls_are_collected
    4_1_7_ensure_login_and_logout_events_are_collected_scored
    4_1_8_ensure_session_initiation_information_is_collected_scored
    4_1_9_ensure_discretionary_access_control_permission_modification_events_are_collected_scored
    4_1_10_ensure_unsuccessful_unauthorized_file_access_attempts_are_collected
    4_1_11_ensure_use_of_privileged_commands_is_collected_scored
    4_1_12_ensure_successful_file_system_mounts_are_collected_scored
    4_1_13_ensure_file_deletion_events_by_users_are_collected_scored
    4_1_14_ensure_changes_to_system_administration_scope_sudoers_is_collected_scored
    4_1_15_ensure_system_administrator_actions_sudolog_are_collected_scored
    4_1_16_ensure_kernel_module_loading_and_unloading_is_collected_scored
    4_1_17_ensure_the_audit_configuration_is_immutable_scored

}

4_1_1_ensure_auditing_is_enabled() {
    4_1_1_1_ensure_auditd_is_installed_scored
    4_1_1_2_ensure_auditd_service_is_enabled_scored
    4_1_1_3_ensure_auditing_for_processes_that_start_prior_to_auditd_is_enabled_scored
    4_1_1_4_ensure_audit_backlog_limit_is_sufficient_scored

}

4_1_1_1_ensure_auditd_is_installed_scored() {
    pass
}

4_1_1_2_ensure_auditd_service_is_enabled_scored() {
    pass
}

4_1_1_3_ensure_auditing_for_processes_that_start_prior_to_auditd_is_enabled_scored() {
    pass
}

4_1_1_4_ensure_audit_backlog_limit_is_sufficient_scored() {
    pass
}

4_1_2_configure_data_retention() {
    4_1_2_1_ensure_audit_log_storage_size_is_configured_scored
    4_1_2_2_ensure_audit_logs_are_not_automatically_deleted_scored
    4_1_2_3_ensure_system_i_disabled_when_audit_logs_are_full_scored

}

4_1_2_1_ensure_audit_log_storage_size_is_configured_scored() {
    pass
}

4_1_2_2_ensure_audit_logs_are_not_automatically_deleted_scored() {
    pass
}

4_1_2_3_ensure_system_i_disabled_when_audit_logs_are_full_scored() {
    pass
}

4_1_3_ensure_events_that_modify_date_and_time_information_are_collected_scored() {
    pass
}

4_1_4_ensure_events_that_modify_user_group_information_are_collected_scored() {
    pass
}

4_1_5_ensure_events_that_modify_the_systems_network_environment_are_collected_scored() {
    pass
}

4_1_6_ensure_events_that_modify_the_systems_mandatory_access_controls_are_collected() {
    pass
}

4_1_7_ensure_login_and_logout_events_are_collected_scored() {
    pass
}

4_1_8_ensure_session_initiation_information_is_collected_scored() {
    pass
}

4_1_9_ensure_discretionary_access_control_permission_modification_events_are_collected_scored() {
    pass
}

4_1_10_ensure_unsuccessful_unauthorized_file_access_attempts_are_collected() {
    pass
}

4_1_11_ensure_use_of_privileged_commands_is_collected_scored() {
    pass
}

4_1_12_ensure_successful_file_system_mounts_are_collected_scored() {
    pass
}

4_1_13_ensure_file_deletion_events_by_users_are_collected_scored() {
    pass
}

4_1_14_ensure_changes_to_system_administration_scope_sudoers_is_collected_scored() {
    pass
}

4_1_15_ensure_system_administrator_actions_sudolog_are_collected_scored() {
    pass
}

4_1_16_ensure_kernel_module_loading_and_unloading_is_collected_scored() {
    pass
}

4_1_17_ensure_the_audit_configuration_is_immutable_scored() {
    pass
}

4_2_configure_logging() {
    4_2_1_configure_rsyslog
    4_2_2_configure_journald
    4_2_3_ensure_permissions_on_all_logfiles_are_configured_scored

}

4_2_1_configure_rsyslog() {

    4_2_1_1_ensure_rsyslog_is_installed_scored
    4_2_1_2_ensure_rsyslog_service_is_enabled_scored
    4_2_1_3_ensure_logging_is_configured_not_scored
    4_2_1_4_ensure_rsyslog_default_file_permissions_configured_scored
    4_2_1_5_ensure_rsyslog_is_configured_to_send_logs_to_a_remote_log_host_scored
    4_2_1_6_ensure_remote_rsyslog_messages_are_only_accepted_on_designated_log_hosts_not_scored

}

4_2_1_1_ensure_rsyslog_is_installed_scored() {
    pass
}

4_2_1_2_ensure_rsyslog_service_is_enabled_scored() {
    pass
}

4_2_1_3_ensure_logging_is_configured_not_scored() {
    pass
}

4_2_1_4_ensure_rsyslog_default_file_permissions_configured_scored() {
    pass
}

4_2_1_5_ensure_rsyslog_is_configured_to_send_logs_to_a_remote_log_host_scored() {
    pass
}

4_2_1_6_ensure_remote_rsyslog_messages_are_only_accepted_on_designated_log_hosts_not_scored() {
    pass
}

4_2_2_configure_journald() {
    4_2_2_1_ensure_journald_is_configured_to_send_logs_to_rsyslog_scored
    4_2_2_2_ensure_journald_is_configured_to_compress_large_log_files_scored
    4_2_2_3_ensure_journald_is_configured_to_write_logfiles_to_persistent_disk_scored
}

4_2_2_1_ensure_journald_is_configured_to_send_logs_to_rsyslog_scored() {
    pass
}

4_2_2_2_ensure_journald_is_configured_to_compress_large_log_files_scored() {
    pass
}

4_2_2_3_ensure_journald_is_configured_to_write_logfiles_to_persistent_disk_scored() {
    pass
}

4_2_3_ensure_permissions_on_all_logfiles_are_configured_scored() {
    pass
}

4_3_ensure_logrotate_is_configured_not_scored() {
    pass
}

4_4_ensure_logrotate_assigns_appropriate_permissions_scored() {
    pass
}

5_access_and_authentication_and_authorization() {
    5_1_configure_cron
    5_2_ssh_server_configuration
    5_3_configure_pam
    5_4_user_accounts_and_environment

}

5_1_configure_cron() {
    5_1_1_ensure_cron_daemon_is_enabled_scored
    5_1_2_ensure_permissions_on_etc_crontab_are_configured_scored
    5_1_3_ensure_permissions_on_etc_cron_hourly_are_configured_scored
    5_1_4_ensure_permissions_on_etc_cron_daily_are_configured_scored
    5_1_5_ensure_permissions_on_etc_cron_weekly_are_configured_scored
    5_1_6_ensure_permissions_on_etc_cron_monthly_are_configured_scored
    5_1_7_ensure_permissions_on_etc_cron_d_are_configured_scored
    5_1_8_ensure_at_cron_is_restricted_to_authorized_users_scored
}

5_1_1_ensure_cron_daemon_is_enabled_scored() {
    systemctl --now enable cron
}

5_1_2_ensure_permissions_on_etc_crontab_are_configured_scored() {
    chown root:root /etc/crontab
    chmod og-rwx /etc/crontab
}

5_1_3_ensure_permissions_on_etc_cron_hourly_are_configured_scored() {
    chown root:root /etc/cron.hourly
    chmod og-rwx /etc/cron.hourly
}

5_1_4_ensure_permissions_on_etc_cron_daily_are_configured_scored() {
    chown root:root /etc/cron.daily
    chmod og-rwx /etc/cron.daily
}

5_1_5_ensure_permissions_on_etc_cron_weekly_are_configured_scored() {
    chown root:root /etc/cron.weekly
    chmod og-rwx /etc/cron.weekly
}

5_1_6_ensure_permissions_on_etc_cron_monthly_are_configured_scored() {
    chown root:root /etc/cron.monthly
    chmod og-rwx /etc/cron.monthly
}

5_1_7_ensure_permissions_on_etc_cron_d_are_configured_scored() {
    chown root:root /etc/cron.d
    chmod og-rwx /etc/cron.d
}

5_1_8_ensure_at_cron_is_restricted_to_authorized_users_scored() {
    rm /etc/cron.deny
    touch /etc/cron.allow
    chown root:root /etc/cron.allow
    chmod g-wx,o-rwx /etc/cron.allow
    rm /etc/at.deny
    touch /etc/at.allow
    chown root:root /etc/at.allow
    chmod g-wx,o-rwx /etc/at.allow
}


5_2_ssh_server_configuration() {
    5_2_1_ensure_permissions_on_etc_ssh_sshd_config_are_configured_scored
    5_2_2_ensure_permissions_on_ssh_private_host_key_files_are_configured_scored
    5_2_3_ensure_permissions_on_ssh_public_host_key_files_are_configured_scored
    5_2_4_ensure_ssh_protocol_is_not_set_to_1_scored
    5_2_5_ensure_ssh_logLevel_is_appropriate_scored
    5_2_6_ensure_ssh_x11_forwarding_is_disabled_scored
    5_2_7_ensure_ssh_maxAuthTries_is_set_to_4_or_less_scored
    5_2_8_ensure_ssh_ignoreRhosts_is_enabled_scored
    5_2_9_ensure_ssh_hostbasedAuthentication_is_disabl
    5_2_10_ensure_ssh_root_login_is_disabled_scored
    5_2_11_ensure_ssh_permitemptypasswords_is_disabled_scored
    5_2_12_ensure_ssh_permitUserenvironment_is_disabled_scored
    5_2_13_ensure_only_strong_ciphers_are_used_scored
    5_2_14_ensure_only_strong_mac_algorithms_are_used_scored
    5_2_15_ensure_only_strong_key_exchange_algorithms_are_used_scored
    5_2_16_ensure_ssh_idle_timeout_interval_is_configured_scored
    5_2_17_ensure_ssh_LogingraceTime_is_set_to_one_minute_or_less_scored
    5_2_18_ensure_ssh_access_is_limited_scored
    5_2_19_ensure_ssh_warning_banner_is_configured_scored
    5_2_20_ensure_ssh_pam_is_enabled_scored
    5_2_21_ensure_ssh_allowTcpforwarding_is_disabled_scored
    5_2_22_ensure_ssh_maxStartups_is_configured_scored
    5_2_23_ensure_ssh_maxSessions_is_limited_scored

}

5_2_1_ensure_permissions_on_etc_ssh_sshd_config_are_configured_scored() {
    chown root:root /etc/ssh/sshd_config
    chmod og-rwx /etc/ssh/sshd_config
}

5_2_2_ensure_permissions_on_ssh_private_host_key_files_are_configured_scored() {
    find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chown root:root {} \;
    find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chmod 0600 {} \;
}

5_2_3_ensure_permissions_on_ssh_public_host_key_files_are_configured_scored() {
    find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chmod go-wx {} \;
    find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chown root:root {} \;
}

5_2_4_ensure_ssh_protocol_is_not_set_to_1_scored() {
    echo "Protocol 2" >> /etc/ssh/sshd_config
}

5_2_5_ensure_ssh_logLevel_is_appropriate_scored() {
    echo "we dont need this"
}

5_2_6_ensure_ssh_x11_forwarding_is_disabled_scored() {
    sed -i '/X11Forwarding/d' /etc/ssh/sshd_config
    echo "X11Forwarding no" >> /etc/ssh/sshd_config
}

5_2_7_ensure_ssh_maxAuthTries_is_set_to_4_or_less_scored() {
    sed -i '/MaxAuthTries/d' /etc/ssh/sshd_config
    echo "MaxAuthTries 3" >> /etc/ssh/sshd_config
}

5_2_8_ensure_ssh_ignoreRhosts_is_enabled_scored() {
    sed -i '/IgnoreRhosts/d' /etc/ssh/sshd_config
    echo "IgnoreRhosts yes" >> /etc/ssh/sshd_config
}

5_2_9_ensure_ssh_hostbasedAuthentication_is_disabl() {
    sed -i '/HostbasedAuthentication/d' /etc/ssh/sshd_config
    echo "HostbasedAuthentication no" >> /etc/ssh/sshd_config
}

5_2_10_ensure_ssh_root_login_is_disabled_scored() {
    sed -i '/PermitRootLogin/d' /etc/ssh/sshd_config
    echo "PermitRootLogin no" >> /etc/ssh/sshd_config
}

5_2_11_ensure_ssh_permitemptypasswords_is_disabled_scored() {
    sed -i '/PermitEmptyPasswords/d' /etc/ssh/sshd_config
    echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
}

5_2_12_ensure_ssh_permitUserenvironment_is_disabled_scored() {
    sed -i '/PermitUserEnvironment/d' /etc/ssh/sshd_config
    echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
}

5_2_13_ensure_only_strong_ciphers_are_used_scored() {
    echo "we dont need"
}

5_2_14_ensure_only_strong_mac_algorithms_are_used_scored() {
    echo "we dont need"
}

5_2_15_ensure_only_strong_key_exchange_algorithms_are_used_scored() {
    echo "we dont need"
}

5_2_16_ensure_ssh_idle_timeout_interval_is_configured_scored() {
    sed -i '/ClientAliveInterval/d' /etc/ssh/sshd_config
    echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config
    sed -i '/ClientAliveCountMax/d' /etc/ssh/sshd_config
    echo "ClientAliveCountMax 0" >> /etc/ssh/sshd_config
}

5_2_17_ensure_ssh_LogingraceTime_is_set_to_one_minute_or_less_scored() {
    sed -i '/LoginGraceTime/d' /etc/ssh/sshd_config
    echo "LoginGraceTime 60" >> /etc/ssh/sshd_config
}

5_2_18_ensure_ssh_access_is_limited_scored() {
    sed -i '/AllowUsers/d' /etc/ssh/sshd_config
    sed -i '/AllowGroups/d' /etc/ssh/sshd_config
    sed -i '/DenyUsers/d' /etc/ssh/sshd_config
    sed -i '/DenyGroups/d' /etc/ssh/sshd_config
    echo "DenyUsers root" >> /etc/ssh/sshd_config
    echo "DenyGroups root" >> /etc/ssh/sshd_config
    # allow user ?!
}

5_2_19_ensure_ssh_warning_banner_is_configured_scored() {
    sed -i '/Banner/d' /etc/ssh/sshd_config
    echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
}

5_2_20_ensure_ssh_pam_is_enabled_scored() {
    echo "we dont need"
}

5_2_21_ensure_ssh_allowTcpforwarding_is_disabled_scored() {
    sed -i '/AllowTcpForwarding/d' /etc/ssh/sshd_config
    echo "AllowTcpForwarding no" >> /etc/ssh/sshd_config
}

5_2_22_ensure_ssh_maxStartups_is_configured_scored() {
    sed -i '/maxstartups/d' /etc/ssh/sshd_config
    echo "maxstartups 10:30:60" >> /etc/ssh/sshd_config
}

5_2_23_ensure_ssh_maxSessions_is_limited_scored() {
    sed -i '/MaxSessions/d' /etc/ssh/sshd_config
    echo "MaxSessions 1" >> /etc/ssh/sshd_config
}

5_3_configure_pam() {
    5_3_1_ensure_password_creation_requirements_are_configured_scored
    5_3_2_ensure_lockout_for_failed_password_attempts_is_configured_scored
    5_3_3_ensure_password_reuse_is_limited_scored
    5_3_4_ensure_password_hashing_algorithm_is_sha_512_scored
}

5_3_1_ensure_password_creation_requirements_are_configured_scored() {
    echo "we dont need this"
}

5_3_2_ensure_lockout_for_failed_password_attempts_is_configured_scored() {
    echo "we dont need this"
}

5_3_3_ensure_password_reuse_is_limited_scored() {
    echo "we dont need this"
}

5_3_4_ensure_password_hashing_algorithm_is_sha_512_scored() {
    echo "we dont need this"
}

5_4_user_accounts_and_environment() {
    5_4_1_set_shadow_password_Suite_parameters
    5_4_2_ensure_system_accounts_are_secured_scored
    5_4_3_ensure_default_group_for_the_root_account_is_gid_0_scored
    5_4_4_ensure_default_user_umask_is_027_or_more_restrictive_scored
    5_4_5_ensure_default_user_shell_timeout_is_900_seconds_or_less_scored
}

5_4_1_set_shadow_password_suite_parameters() {
    5_4_1_1_ensure_password_expiration_is_365_days_or_less_scored
    5_4_1_2_ensure_minimum_days_between_password_changes_is_configuredscored
    5_4_1_3_ensure_password_expiration_warning_days_is_7_or_more_scored
    5_4_1_4_ensure_inactive_password_lock_is_30_days_or_less_scored
    5_4_1_5_ensure_all_users_last_password_change_date_is_in_the_past_scored
}

5_4_1_1_ensure_password_expiration_is_365_days_or_less_scored() {
    echo "we dont need"
}

5_4_1_2_ensure_minimum_days_between_password_changes_is_configuredscored() {
    echo "we dont need"
}

5_4_1_3_ensure_password_expiration_warning_days_is_7_or_more_scored() {
    echo "we dont need"
}

5_4_1_4_ensure_inactive_password_lock_is_30_days_or_less_scored() {
    echo "we dont need"
}

5_4_1_5_ensure_all_users_last_password_change_date_is_in_the_past_scored() {
    echo "we dont need"
}


5_4_2_ensure_system_accounts_are_secured_scored() {
    awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && \
    $1!~/^\+/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' && \
    $7!="'"$(which nologin)"'" && $7!="/bin/false") {print $1}' /etc/passwd | \
    while read -r user; do usermod -s "$(which nologin)" "$user"; done
    awk -F: '($1!="root" && $1!~/^\+/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' \
    /etc/login.defs)"') {print $1}' /etc/passwd | xargs -I '{}' passwd -S '{}' | \
    awk '($2!="L" && $2!="LK") {print $1}' | while read -r user; do usermod -L \
    "$user"; done
}

5_4_3_ensure_default_group_for_the_root_account_is_gid_0_scored() {
    usermod -g 0 root
}

5_4_4_ensure_default_user_umask_is_027_or_more_restrictive_scored() {
    sed -i '/umask/d' /etc/bash.bashrc
    sed -i '/umask/d' /etc/profile
    sed -i '/umask/d' /etc/profile.d/*.sh
    echo "umask 027" >> /etc/bash.bashrc
    echo "umask 027" >> /etc/profile
    echo "umask 027" >> /etc/profile.d/custom_naad.sh
}

5_4_5_ensure_default_user_shell_timeout_is_900_seconds_or_less_scored() {
    sed -i '/TMOUT/d' /etc/bash.bashrc
    sed -i '/TMOUT/d' /etc/profile
    sed -i '/TMOUT/d' /etc/profile.d/*.sh
    echo "readonly TMOUT=900 ; export TMOUT" >> /etc/bash.bashrc
    echo "readonly TMOUT=900 ; export TMOUT" >> /etc/profile
    echo "readonly TMOUT=900 ; export TMOUT" >> /etc/profile.d/custom_naad.sh
}

5_5_ensure_root_login_is_restricted_to_system_console_not_scored() {
    pass
}

5_6_ensure_access_to_the_su_command_is_restricted_scored() {
    groupadd sugroup
    echo "auth required pam_wheel.so use_uid group=sugroup" >> /etc/pam.d/su
}


6_System_maintenance() {
    6_1_system_file_permissions
    6_2_user_and_group_settings

}

6_1_system_file_permissions() {
    6_1_1_audit_system_file_permissions_not_scored
    6_1_2_ensure_permissions_on_etc_passwd_are_configured_scored
    6_1_3_ensure_permissions_on_etc_gshadow_are_configured_scored
    6_1_4_ensure_permissions_on_etc_shadow_are_configured_scored
    6_1_5_ensure_permissions_on_etc_group_are_configured_scored
    6_1_6_ensure_permissions_on_etc_passwd_are_configured_scored
    6_1_7_ensure_permissions_on_etc_shadow_are_configured_scored
    6_1_8_ensure_permissions_on_etc_group_are_configured_scored
    6_1_9_ensure_permissions_on_etc_gshadow_are_configured_scored
    6_1_10_ensure_no_world_writable_files_exist_scored
    6_1_11_ensure_no_unowned_files_or_directories_exist_scored
    6_1_12_ensure_no_ungrouped_files_or_directories_exist_scored
    6_1_13_audit_suid_executables_scored
    6_1_14_audit_sgid_executables_scored

}

6_1_1_audit_system_file_permissions_not_scored() {
    echo "we dont need"
}

6_1_2_ensure_permissions_on_etc_passwd_are_configured_scored() {
    chown root:root /etc/passwd
    chmod 644 /etc/passwd
}

6_1_3_ensure_permissions_on_etc_gshadow_are_configured_scored() {
    chown root:root /etc/gshadow-
    chown root:shadow /etc/gshadow-
    chmod o-rwx,g-wx /etc/gshadow-
}

6_1_4_ensure_permissions_on_etc_shadow_are_configured_scored() {
    chmod o-rwx,g-wx /etc/shadow
    chown root:shadow /etc/shadow
}

6_1_5_ensure_permissions_on_etc_group_are_configured_scored() {
    chown root:root /etc/group
    chmod 644 /etc/group
}

6_1_6_ensure_permissions_on_etc_passwd_are_configured_scored() {
    chown root:root /etc/passwd-
    chmod u-x,go-rwx /etc/passwd-
}

6_1_7_ensure_permissions_on_etc_shadow_are_configured_scored() {
    chown root:shadow /etc/shadow-
    chmod u-x,go-rwx /etc/shadow-
}

6_1_8_ensure_permissions_on_etc_group_are_configured_scored() {
    chown root:root /etc/group-
    chmod u-x,go-rwx /etc/group-
}

6_1_9_ensure_permissions_on_etc_gshadow_are_configured_scored() {
    chown root:shadow /etc/gshadow
    chmod o-rwx,g-wx /etc/gshadow
}

6_1_10_ensure_no_world_writable_files_exist_scored() {
    df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev \
    -type f -perm -0002 > world_writable_files_list.txt
    while read p; do
        chmod o-w "$p"
    done <world_writable_files_list.txt
    rm -f world_writable_files_list.txt

}

6_1_11_ensure_no_unowned_files_or_directories_exist_scored() {
    df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev \
    -nouser > unowned_files_or_directories_list.txt
    while read p; do
        rm -rf "$p"
    done <unowned_files_or_directories_list.txt
    rm -f unowned_files_or_directories_list.txt
}

6_1_12_ensure_no_ungrouped_files_or_directories_exist_scored() {
    df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev \
    -nogroup > ungrouped_files_or_directories_list.txt
    while read p; do
        rm -rf "$p"
    done <ungrouped_files_or_directories_list.txt
    rm -f ungrouped_files_or_directories_list.txt    
}

6_1_13_audit_suid_executables_scored() {
    df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev \
    -type f -perm -4000 > suid_executables_files_list.txt
    while read p; do
        chmod ug-s "$p"
    done <suid_executables_files_list.txt
    rm -f suid_executables_files_list.txt

}

6_1_14_audit_sgid_executables_scored() {
    df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev \
    -type f -perm -2000 > sgid_executables_files_list.txt
    while read p; do
        chmod ug-s "$p"
    done <sgid_executables_files_list.txt
    rm -f sgid_executables_files_list.txt
}

6_2_user_and_group_settings() {
    6_2_1_ensure_password_fields_are_not_empty_scored
    6_2_2_ensure_no_legacy_plus_entries_exist_in_etc_passwd_scored
    6_2_3_ensure_all_users_home_directories_exist_scored
    6_2_4_ensure_no_legacy_plus_entries_exist_in_etc_shadow_scored
    6_2_5_ensure_no_legacy_plus_entries_exist_in_etc_group_scored
    6_2_6_ensure_root_is_the_only_uid_0_account_scored
    6_2_7_ensure_root_path_integrity_scored
    6_2_8_ensure_users_home_directories_permissions_are_750_or_more_restrictive_scored
    6_2_9_ensure_users_own_their_home_directories_scored
    6_2_10_ensure_users_dot_files_are_not_group_or_world_writable_scored
    6_2_11_ensure_no_users_have_dot_forward_files_scored
    6_2_12_ensure_no_users_have_dot_netrc_files_scored
    6_2_13_ensure_users_dot_netrc_Files_are_not_group_or_world_accessible_scored
    6_2_14_ensure_no_users_have_dot_rhosts_files_scored
    6_2_15_ensure_all_groups_in_etc_passwd_exist_in_etc_group_scored
    6_2_16_ensure_no_duplicate_uids_exist_scored
    6_2_17_ensure_no_duplicate_gids_exist_scored
    6_2_18_ensure_no_duplicate_user_names_exist_scored
    6_2_19_ensure_no_duplicate_group_names_exist_scored
    6_2_20_ensure_shadow_group_is_empty_scored

}

6_2_1_ensure_password_fields_are_not_empty_scored() {
    awk -F: '($2 == "" ) { print $1}' /etc/shadow  > users_with_password_fields_empty.txt
    while read p; do
        passwd -l $p
    done <users_with_password_fields_empty.txt
    rm -f users_with_password_fields_empty.txt
}

6_2_2_ensure_no_legacy_plus_entries_exist_in_etc_passwd_scored() {
    grep '^\+:' /etc/passwd > legacy_plus_entries_exist_in_etc_passwd_list.txt
    while read p; do
        sed -i "/$p/d" /etc/passwd
    done <legacy_plus_entries_exist_in_etc_passwd_list.txt
    rm -f legacy_plus_entries_exist_in_etc_passwd_list.txt
}

6_2_3_ensure_all_users_home_directories_exist_scored() {
    echo "we dont need this"
}

6_2_4_ensure_no_legacy_plus_entries_exist_in_etc_shadow_scored() {
    grep '^\+:' /etc/shadow > legacy_plus_entries_exist_in_etc_shadow_list.txt
    while read p; do
        sed -i "/$p/d" /etc/shadow
    done <legacy_plus_entries_exist_in_etc_shadow_list.txt
    rm -f legacy_plus_entries_exist_in_etc_shadow_list.txt
}

6_2_5_ensure_no_legacy_plus_entries_exist_in_etc_group_scored() {
    grep '^\+:' /etc/group > legacy_plus_entries_exist_in_etc_group_list.txt
    while read p; do
        sed -i "/$p/d" /etc/group
    done <legacy_plus_entries_exist_in_etc_group_list.txt
    rm -f legacy_plus_entries_exist_in_etc_group_list.txt
}

6_2_6_ensure_root_is_the_only_uid_0_account_scored() {
    awk -F: '($3 == 0) { print $1 }' /etc/passwd > uid_0_account_list.txt
    sed -i '/root/d' uid_0_account_list.txt
    while read p; do
        deluser $p
    done <uid_0_account_list.txt
    rm -f uid_0_account_list.txt
}

6_2_7_ensure_root_path_integrity_scored() {
    #path ro bayad daghigh bezarim inja
}

6_2_8_ensure_users_home_directories_permissions_are_750_or_more_restrictive_scored() {
    grep -E -v '^(halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "'"$(which \
    nologin)"'" && $7 != "/bin/false") { print $1 " " $6 }' | while read user \
    dir; do
        chmod o-rwx,g-w $dir
    done    
}

6_2_9_ensure_users_own_their_home_directories_scored() {
    grep -E -v '^(halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "'"$(which \
    nologin)"'" && $7 != "/bin/false") { print $1 " " $6 }' | while read user \
    dir; do
        chown -R $user:$user $dir
    done
}

6_2_10_ensure_users_dot_files_are_not_group_or_world_writable_scored() {
    grep -E -v '^(halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "'"$(which \
    nologin)"'" && $7 != "/bin/false") { print $1 " " $6 }' | while read user \
    dir; do
        for file in $dir/.[A-Za-z0-9]*; do
            chmod g-w,o-w $file
        done
    done
}

6_2_11_ensure_no_users_have_dot_forward_files_scored() {
    grep -E -v '^(root|halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != \
    "'"$(which nologin)"'" && $7 != "/bin/false") { print $1 " " $6 }' | while \
    read user dir; do
        echo "$dir" >> dot_forward_files_list.txt
    done
    while read p; do
        rm -f $p/.netrc
    done <dot_forward_files_list.txt
    rm -f dot_forward_files_list.txt
}

6_2_12_ensure_no_users_have_dot_netrc_files_scored() {
    grep -E -v '^(root|halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != \
    "'"$(which nologin)"'" && $7 != "/bin/false") { print $1 " " $6 }' | while \
    read user dir; do
        echo "$dir" >> dot_netrc_Files_list.txt
    done
    while read p; do
        rm -f $p/.netrc
    done <dot_netrc_Files_list.txt
    rm -f dot_netrc_Files_list.txt
}

6_2_13_ensure_users_dot_netrc_Files_are_not_group_or_world_accessible_scored() {
    echo "we remove this file"
}

6_2_14_ensure_no_users_have_dot_rhosts_files_scored() {
    find /home /root -name .rhosts -print -exec rm{} \;
}

6_2_15_ensure_all_groups_in_etc_passwd_exist_in_etc_group_scored() {
    #چک شود که دقیقا ستون پنجم اسم گروه باشد
    # مشکل داره و روی دب باید تست بشه
    for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
        grep -q -P "^.*?:[^:]*:$i:" /etc/group
        if [ $? -ne 0 ]; then
            echo "$i" > groups_in_etc_passwd_not_exist_in_etc_group.txt
        fi
    done
    while read p; do
        sed -i "/$p/d" /etc/passwd
    done <groups_in_etc_passwd_not_exist_in_etc_group.txt
    rm -f groups_in_etc_passwd_not_exist_in_etc_group.txt
}

6_2_16_ensure_no_duplicate_uids_exist_scored() {
    cut -f3 -d":" /etc/passwd | sort -n | uniq -c | while read x ; do
            [ -z "$x" ] && break
            set - $x
            if [ $1 -gt 1 ]; then
                    users=$(awk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | xargs)
                    for i in $users
                    do
                            echo $i >> duplicate_uids.txt
                    done
            fi
    done
    while read p; do
        sed -i "/$p/d" /etc/passwd
    done <duplicate_uids.txt
    rm -f duplicate_uids.txt
}

6_2_17_ensure_no_duplicate_gids_exist_scored() {
    cut -d: -f3 /etc/group | sort | uniq -d | while read x ; do
	    echo "$x" > duplicate_gids.txt
    done
    while read p; do
	    grep $p /etc/group >> duplicate_gids_names.txt
    done <duplicate_gids.txt
    rm -f duplicate_gids.txt
    while read p; do
        sed -i "/$p/d" /etc/group
    done <duplicate_gids_names.txt
    rm -f duplicate_gids_names.txt

}

6_2_18_ensure_no_duplicate_user_names_exist_scored() {
    cut -d: -f1 /etc/passwd | sort | uniq -d | while read x
    do echo "${x}" > duplicate_user_name.txt
    done
    while read p; do
        sed -i "/$p/d" /etc/passwd
    done <duplicate_user_name.txt
    rm -f duplicate_user_name.txt
}

6_2_19_ensure_no_duplicate_group_names_exist_scored() {
    cut -d: -f1 /etc/group | sort | uniq -d | while read x
    do echo "${x}" > duplicate_group_name.txt
    done
    while read p; do
        sed -i "/$p/d" /etc/group
    done <duplicate_group_name.txt
    rm -f duplicate_group_name.txt
}

6_2_20_ensure_shadow_group_is_empty_scored() {
    awk -F: '{ print $1}' /etc/passwd > user.txt
    while read p; do
        deluser $p shadow
    done <user.txt
    rm -f user.txt
}

main
