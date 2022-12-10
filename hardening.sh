#!/bin/bash

#CiS debian Linux 10 benchmark
#v1.0.0 - 02-13-202

main() {
    1_initial_setup
    2_services
    3_network_configuration
    4_logging_and_auditing
    5_access_and_authentication_and_authorization
    6_System_maintenance
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

}

1_1_1_2_ensure_mounting_of_jffs2_filesystems_is_disabled_scored() {

}

1_1_1_3_ensure_mounting_of_hfs_filesystems_is_disabled_scored() {

}

1_1_1_4_ensure_mounting_of_hfsplus_filesystems_is_disabled_scored() {

}

1_1_1_5_ensure_mounting_of_squashfs_filesystems_is_disabled_scored() {

}

1_1_1_6_ensure_mounting_of_udf_filesystem_is_disabled_scored() {

}

1_1_1_7_ensure_mounting_of_fat_filesystems_is_limited_not_scored() {

}

1_1_2_ensure_tmp_is_configured_scored() {

}

1_1_3_ensure_nodev_option_set_on_tmp_partition_scored() {

}

1_1_4_ensure_nosuid_option_set_on_tmp_partition_scored() {

}

1_1_5_ensure_noexec_option_set_on_tmp_partition_scored() {

}

1_1_6_ensure_separate_partition_exists_for_var_scored() {

}

1_1_7_ensure_separate_partition_exists_for_var_tmp_scored() {

}

1_1_8_ensure_nodev_option_set_on_var_tmp_partition_scored() {

}

1_1_9_ensure_nosuid_option_set_on_var_tmp_partition_scored() {

}

1_1_10_ensure_noexec_option_set_on_var_tmp_partition_scored() {

}

1_1_11_ensure_separate_partition_exists_for_var_log_scored() {

}

1_1_12_ensure_separate_partition_exists_for_var_log_audit_scored() {

}

1_1_13_ensure_separate_partition_exists_for_home_scored() {

}

1_1_14_ensure_nodev_option_set_on_home_partition_scored() {

}

1_1_15_ensure_nodev_option_set_on_dev_shm_partition_scored() {

}

1_1_16_ensure_nosuid_option_set_on_dev_shm_partition_scored(){

}

1_1_17_ensure_noexec_option_set_on_dev_shm_partition_scored(){

}

1_1_18_ensure_nodev_option_set_on_removable_media_partitions_not_scored() {

}

1_1_19_ensure_nosuid_option_set_on_removable_media_partitions_not_scored() {

}

1_1_20_ensure_noexec_option_set_on_removable_media_partitions_not_scored() {

}

1_1_21_ensure_sticky_bit_is_set_on_all_world_writable_directories_scored() {

}

1_1_22_disable_automounting_scored() {

}

1_1_23_disable_usb_storage_scored() {

}

1_2_configure_software_updates() {
    1_2_1_ensure_package_manager_repositories_are_configured_not_scored
    1_2_2_ensure_gpg_keys_are_configured_not_scored
}

1_2_1_ensure_package_manager_repositories_are_configured_not_scored() {

}

1_2_2_ensure_gpg_keys_are_configured_not_scored() {

}

1_3_configure_sudo() {
    1_3_1_ensure_sudo_is_installed_scored
    1_3_2_ensure_sudo_commands_use_pty_scored
    1_3_3_ensure_sudo_log_file_exists_scored
}

1_3_1_ensure_sudo_is_installed_scored() {

}

1_3_2_ensure_sudo_commands_use_pty_scored() {

}

1_3_3_ensure_sudo_log_file_exists_scored() {

}

1_4_filesystem_integrity_checking() {
    1_4_1_ensure_aide_is_installed_scored
    1_4_2_ensure_filesystem_integrity_is_regularly_checked_scored
}

1_4_1_ensure_aide_is_installed_scored() {

}

1_4_2_ensure_filesystem_integrity_is_regularly_checked_scored() {

}

1_5_secure_boot_settings() {
    1_5_1_ensure_permissions_on_bootloader_config_are_configured_scored
    1_5_2_ensure_bootloader_password_is_set_scored
    1_5_3_ensure_authentication_required_for_single_user_mode_scored
}

1_5_1_ensure_permissions_on_bootloader_config_are_configured_scored() {

}

1_5_2_ensure_bootloader_password_is_set_scored() {

}

1_5_3_ensure_authentication_required_for_single_user_mode_scored() {

}

1_6_additional_process_hardening() {
    1_6_1_ensure_xd_nx_support_is_enabled_scored
    1_6_2_ensure_address_space_layout_randomization_aslr_is_enabled_scored
    1_6_3_ensure_prelink_is_disabled_scored
    1_6_4_ensure_core_dumps_are_restricted_scored
}

1_6_1_ensure_xd_nx_support_is_enabled_scored() {

}

1_6_2_ensure_address_space_layout_randomization_aslr_is_enabled_scored() {

}

1_6_3_ensure_prelink_is_disabled_scored() {

}

1_6_4_ensure_core_dumps_are_restricted_scored() {

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

}

1_7_1_2_ensure_apparmor_is_enabled_in_the_bootloader_configuration_scored() {

}

1_7_1_3_ensure_all_apparmor_profiles_are_in_enforce_or_complain_mode_scored() {

}

1_7_1_4_ensure_all_apparmor_profiles_are_enforcing_scored() {

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

}

1_8_1_2_ensure_local_login_warning_banner_is_configured_properly_scored() {

}

1_8_1_3_ensure_remote_login_warning_banner_is_configured_properly_scored() {

}

1_8_1_4_ensure_permissions_on_etc_motd_are_configured_scored() {

}

1_8_1_5_ensure_permissions_on_etc_issue_are_configured_scored() {

}

1_8_1_6_ensure_permissions_on_etc_issue_net_are_configured_scored() {

}

1_8_2_ensur_gdm_login_banner_is_configured_scored() {

}

1_9_ensure_updates_and_patches_and_additional_security_software_are_installed_not_scored() {

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

}

2_1_2_ensure_openbsd_inetd_is_not_installed_scored() {

}

2_2_special_purpose_services() {
    2_2_1_time_synchronization
    2_2_2_ensure_x_window_system_is_not_installed_scored
    2_2_3_ensure_avahi_server_is_not_enabled_scored
    2_2_4_ensure_cups_is_not_enabled_scored
    2_2_5_ensure_dhcp_server_is_not_enabled_scored
    2_2_6_ensure_ldap_server_is_not_enabled_scored
    2_2_7_ensure_nfs_and_rpc_are_not_enabled_scored
    2_2_8_ensure_dns_Server_is_not_enabled_scored
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

}

2_2_1_2_ensure_systemd_timesyncd_is_configured_not_scored() {

}

2_2_1_3_ensure_chrony_is_configured_scored() {

}

2_2_1_4_ensure_ntp_is_configured_scored() {

}

2_2_2_ensure_x_window_system_is_not_installed_scored() {

}

2_2_3_ensure_avahi_server_is_not_enabled_scored() {

}

2_2_4_ensure_cups_is_not_enabled_scored() {

}

2_2_5_ensure_dhcp_server_is_not_enabled_scored() {

}

2_2_6_ensure_ldap_server_is_not_enabled_scored() {

}

2_2_7_ensure_nfs_and_rpc_are_not_enabled_scored() {

}

2_2_8_ensure_dns_Server_is_not_enabled_scored() {

}

2_2_9_ensure_ftp_server_is_not_enabled_scored() {

}

2_2_10_ensure_http_server_is_not_enabled_scored() {

}

2_2_11_ensure_email_services_are_not_enabled_scored() {

}

2_2_12_ensure_samba_is_not_enabled_scored() {

}

2_2_13_ensure_http_proxy_server_is_not_enabled_scored() {

}

2_2_14_ensure_snmp_server_is_not_enabled_scored() {

}

2_2_15_ensure_mail_transfer_agent_is_configured_for_local_only_mode_scored() {

}

2_2_16_ensure_rsync_service_is_not_enabled_scored() {

}

2_2_17_ensure_nis_server_is_not_enabled_scored() {

}


2_3_service_clients() {
    2_3_1_ensure_nis_client_is_not_installed_scored
    2_3_2_ensure_rsh_client_is_not_installed_scored
    2_3_3_ensure_talk_client_is_not_installed_scored
    2_3_4_ensure_telnet_client_is_not_installed_scored
    2_3_5_ensure_ldap_client_is_not_installed_scored

}

2_3_1_ensure_nis_client_is_not_installed_scored() {

}

2_3_2_ensure_rsh_client_is_not_installed_scored() {

}

2_3_3_ensure_talk_client_is_not_installed_scored() {

}

2_3_4_ensure_telnet_client_is_not_installed_scored() {

}

2_3_5_ensure_ldap_client_is_not_installed_scored() {

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

}

3_1_2_ensure_wireless_interfaces_are_disabled_scored() {

}

3_2_network_parameters_host_only() {
    3_2_1_ensure_packet_redirect_sending_is_disabled_scored
    3_2_2_ensure_ip_forwarding_is_disabled_scored
}

3_2_1_ensure_packet_redirect_sending_is_disabled_scored() {

}

3_2_2_ensure_ip_forwarding_is_disabled_scored() {

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

}

3_3_2_ensure_icmp_redirects_are_not_accepted_scored() {

}

3_3_3_ensure_secure_icmp_redirects_are_not_accepted_scored(){

}

3_3_4_ensure_suspicious_packets_are_logged_scored() {

}

3_3_5_ensure_broadcast_icmp_requests_are_ignored_scored() {

}

3_3_6_ensure_bogus_icmp_responses_are_ignored_scored() {

}

3_3_7_ensure_reverse_path_filtering_is_enabled_scored() {

}

3_3_8_ensure_tcp_syn_cookies_is_enabled_scored() {

}

3_3_9_ensure_ipv6_router_advertisements_are_not_accepted_scored() {

}



3_4_uncommon_network_protocols() {
    3_4_1_ensure_dccp_is_disabled_scored
    3_4_2_ensure_sctp_is_disabled_scored
    3_4_3_ensure_rds_is_disabled_scored
    3_4_4_ensure_tips_is_disabled_scored
}

3_4_1_ensure_dccp_is_disabled_scored() {

}

3_4_2_ensure_sctp_is_disabled_scored() {

}

3_4_3_ensure_rds_is_disabled_scored() {

}

3_4_4_ensure_tips_is_disabled_scored() {

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

}

3_5_2_configure_uncomplicatedfirewall() {
    3_5_2_1_ensure_ufw_service_is_enabled_scored
    3_5_2_2_ensure_default_deny_firewall_policy_scored
    3_5_2_3_ensure_loopback_traffic_is_configured_scored
    3_5_2_4_ensure_outbound_connections_are_configured_not_scored
    3_5_2_5_ensure_firewall_rules_exist_for_all_open_ports_scored
    
}

3_5_2_1_ensure_ufw_service_is_enabled_scored() {

}

3_5_2_2_ensure_default_deny_firewall_policy_scored() {

}

3_5_2_3_ensure_loopback_traffic_is_configured_scored() {

}

3_5_2_4_ensure_outbound_connections_are_configured_not_scored() {

}

3_5_2_5_ensure_firewall_rules_exist_for_all_open_ports_scored() {

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

}

3_5_3_2_ensure_a_table_exists_scored() {

}

3_5_3_3_ensure_base_chains_exist_scored() {

}

3_5_3_4_ensure_loopback_traffic_is_configured_scored() {

}

3_5_3_5_ensure_outbound_and_established_connections_are_configured_not_scored() {

}

3_5_3_6_ensure_default_deny_firewall_policy_scored() {

}

3_5_3_7_ensure_nftables_service_is_enabled_scored() {

}

3_5_3_8_ensure_nftables_rules_are_permanent_scored() {

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

}

3_5_4_1_2_ensure_loopback_traffic_is_configured_scored() {

}

3_5_4_1_3_ensure_outbound_and_established_connections_are_configured_not_scored() {

}

3_5_4_1_4_ensure_firewall_rules_exist_for_all_open_ports_scored() {

}

3_5_4_2_1_ensure_IPv6_default_deny_firewall_policy_scored() {

}

3_5_4_2_2_ensure_IPv6_loopback_traffic_is_configured_scored() {

}

3_5_4_2_3_ensure_IPv6_outbound_and_established_connections_are_configured_not_scored() {

}

3_5_4_2_4_ensure_IPv6_firewall_rules_exist_for_all_open_ports_not_scored() {

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

}

4_1_1_2_ensure_auditd_service_is_enabled_scored() {

}

4_1_1_3_ensure_auditing_for_processes_that_start_prior_to_auditd_is_enabled_scored() {

}

4_1_1_4_ensure_audit_backlog_limit_is_sufficient_scored() {

}

4_1_2_configure_data_retention() {
    4_1_2_1_ensure_audit_log_storage_size_is_configured_scored
    4_1_2_2_ensure_audit_logs_are_not_automatically_deleted_scored
    4_1_2_3_ensure_system_i_disabled_when_audit_logs_are_full_scored

}

4_1_2_1_ensure_audit_log_storage_size_is_configured_scored() {

}

4_1_2_2_ensure_audit_logs_are_not_automatically_deleted_scored() {

}

4_1_2_3_ensure_system_i_disabled_when_audit_logs_are_full_scored() {

}

4_1_3_ensure_events_that_modify_date_and_time_information_are_collected_scored() {

}

4_1_4_ensure_events_that_modify_user_group_information_are_collected_scored() {

}

4_1_5_ensure_events_that_modify_the_systems_network_environment_are_collected_scored() {

}

4_1_6_ensure_events_that_modify_the_systems_mandatory_access_controls_are_collected() {

}

4_1_7_ensure_login_and_logout_events_are_collected_scored() {

}

4_1_8_ensure_session_initiation_information_is_collected_scored() {

}

4_1_9_ensure_discretionary_access_control_permission_modification_events_are_collected_scored() {

}

4_1_10_ensure_unsuccessful_unauthorized_file_access_attempts_are_collected() {

}

4_1_11_ensure_use_of_privileged_commands_is_collected_scored() {

}

4_1_12_ensure_successful_file_system_mounts_are_collected_scored() {

}

4_1_13_ensure_file_deletion_events_by_users_are_collected_scored() {

}

4_1_14_ensure_changes_to_system_administration_scope_sudoers_is_collected_scored() {

}

4_1_15_ensure_system_administrator_actions_sudolog_are_collected_scored() {

}

4_1_16_ensure_kernel_module_loading_and_unloading_is_collected_scored() {

}

4_1_17_ensure_the_audit_configuration_is_immutable_scored() {

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

}

4_2_1_2_ensure_rsyslog_service_is_enabled_scored() {

}

4_2_1_3_ensure_logging_is_configured_not_scored() {

}

4_2_1_4_ensure_rsyslog_default_file_permissions_configured_scored() {

}

4_2_1_5_ensure_rsyslog_is_configured_to_send_logs_to_a_remote_log_host_scored() {

}

4_2_1_6_ensure_remote_rsyslog_messages_are_only_accepted_on_designated_log_hosts_not_scored() {

}

4_2_2_configure_journald() {
    4_2_2_1_ensure_journald_is_configured_to_send_logs_to_rsyslog_scored
    4_2_2_2_ensure_journald_is_configured_to_compress_large_log_files_scored
    4_2_2_3_ensure_journald_is_configured_to_write_logfiles_to_persistent_disk_scored
}

4_2_2_1_ensure_journald_is_configured_to_send_logs_to_rsyslog_scored() {

}

4_2_2_2_ensure_journald_is_configured_to_compress_large_log_files_scored() {

}

4_2_2_3_ensure_journald_is_configured_to_write_logfiles_to_persistent_disk_scored() {

}

4_2_3_ensure_permissions_on_all_logfiles_are_configured_scored() {

}

4_3_ensure_logrotate_is_configured_not_scored() {

}

4_4_ensure_logrotate_assigns_appropriate_permissions_scored() {

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

}

5_1_2_ensure_permissions_on_etc_crontab_are_configured_scored() {

}

5_1_3_ensure_permissions_on_etc_cron_hourly_are_configured_scored() {

}

5_1_4_ensure_permissions_on_etc_cron_daily_are_configured_scored() {

}

5_1_5_ensure_permissions_on_etc_cron_weekly_are_configured_scored() {

}

5_1_6_ensure_permissions_on_etc_cron_monthly_are_configured_scored() {

}

5_1_7_ensure_permissions_on_etc_cron_d_are_configured_scored() {

}

5_1_8_ensure_at_cron_is_restricted_to_authorized_users_scored() {

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

}

5_2_2_ensure_permissions_on_ssh_private_host_key_files_are_configured_scored() {

}

5_2_3_ensure_permissions_on_ssh_public_host_key_files_are_configured_scored() {

}

5_2_4_ensure_ssh_protocol_is_not_set_to_1_scored() {

}

5_2_5_ensure_ssh_logLevel_is_appropriate_scored() {

}

5_2_6_ensure_ssh_x11_forwarding_is_disabled_scored() {

}

5_2_7_ensure_ssh_maxAuthTries_is_set_to_4_or_less_scored() {

}

5_2_8_ensure_ssh_ignoreRhosts_is_enabled_scored() {

}

5_2_9_ensure_ssh_hostbasedAuthentication_is_disabl() {

}

5_2_10_ensure_ssh_root_login_is_disabled_scored() {

}

5_2_11_ensure_ssh_permitemptypasswords_is_disabled_scored() {

}

5_2_12_ensure_ssh_permitUserenvironment_is_disabled_scored() {

}

5_2_13_ensure_only_strong_ciphers_are_used_scored() {

}

5_2_14_ensure_only_strong_mac_algorithms_are_used_scored() {

}

5_2_15_ensure_only_strong_key_exchange_algorithms_are_used_scored() {

}

5_2_16_ensure_ssh_idle_timeout_interval_is_configured_scored() {

}

5_2_17_ensure_ssh_LogingraceTime_is_set_to_one_minute_or_less_scored() {

}

5_2_18_ensure_ssh_access_is_limited_scored() {

}

5_2_19_ensure_ssh_warning_banner_is_configured_scored() {

}

5_2_20_ensure_ssh_pam_is_enabled_scored() {

}

5_2_21_ensure_ssh_allowTcpforwarding_is_disabled_scored() {

}

5_2_22_ensure_ssh_maxStartups_is_configured_scored() {

}

5_2_23_ensure_ssh_maxSessions_is_limited_scored() {

}

5_3_configure_pam() {
    5_3_1_ensure_password_creation_requirements_are_configured_scored
    5_3_2_ensure_lockout_for_failed_password_attempts_is_configured_scored
    5_3_3_ensure_password_reuse_is_limited_scored
    5_3_4_ensure_password_hashing_algorithm_is_Sha_512_scored
}

5_3_1_ensure_password_creation_requirements_are_configured_scored() {

}

5_3_2_ensure_lockout_for_failed_password_attempts_is_configured_scored() {

}

5_3_3_ensure_password_reuse_is_limited_scored() {

}

5_3_4_ensure_password_hashing_algorithm_is_Sha_512_scored() {

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

}

5_4_1_2_ensure_minimum_days_between_password_changes_is_configuredscored() {

}

5_4_1_3_ensure_password_expiration_warning_days_is_7_or_more_scored() {

}

5_4_1_4_ensure_inactive_password_lock_is_30_days_or_less_scored() {

}

5_4_1_5_ensure_all_users_last_password_change_date_is_in_the_past_scored() {

}


5_4_2_ensure_system_accounts_are_secured_scored() {

}

5_4_3_ensure_default_group_for_the_root_account_is_gid_0_scored() {

}

5_4_4_ensure_default_user_umask_is_027_or_more_restrictive_scored() {

}

5_4_5_ensure_default_user_shell_timeout_is_900_seconds_or_less_scored() {

}

5_5_ensure_root_login_is_restricted_to_system_console_not_scored() {

}

5_6_ensure_access_to_the_su_command_is_restricted_scored() {

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

}

6_1_2_ensure_permissions_on_etc_passwd_are_configured_scored() {

}

6_1_3_ensure_permissions_on_etc_gshadow_are_configured_scored() {

}

6_1_4_ensure_permissions_on_etc_shadow_are_configured_scored() {

}

6_1_5_ensure_permissions_on_etc_group_are_configured_scored() {

}

6_1_6_ensure_permissions_on_etc_passwd_are_configured_scored() {

}

6_1_7_ensure_permissions_on_etc_shadow_are_configured_scored() {

}

6_1_8_ensure_permissions_on_etc_group_are_configured_scored() {

}

6_1_9_ensure_permissions_on_etc_gshadow_are_configured_scored() {

}

6_1_10_ensure_no_world_writable_files_exist_scored() {

}

6_1_11_ensure_no_unowned_files_or_directories_exist_scored() {

}

6_1_12_ensure_no_ungrouped_files_or_directories_exist_scored() {

}

6_1_13_audit_suid_executables_scored() {

}

6_1_14_audit_sgid_executables_scored() {

}

6_2_user_and_group_settings()_{
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

}

6_2_2_ensure_no_legacy_plus_entries_exist_in_etc_passwd_scored() {

}

6_2_3_ensure_all_users_home_directories_exist_scored() {

}

6_2_4_ensure_no_legacy_plus_entries_exist_in_etc_shadow_scored() {

}

6_2_5_ensure_no_legacy_plus_entries_exist_in_etc_group_scored() {

}

6_2_6_ensure_root_is_the_only_uid_0_account_scored() {

}

6_2_7_ensure_root_path_integrity_scored() {

}

6_2_8_ensure_users_home_directories_permissions_are_750_or_more_restrictive_scored() {

}

6_2_9_ensure_users_own_their_home_directories_scored() {

}

6_2_10_ensure_users_dot_files_are_not_group_or_world_writable_scored() {

}

6_2_11_ensure_no_users_have_dot_forward_files_scored() {

}

6_2_12_ensure_no_users_have_dot_netrc_files_scored() {

}

6_2_13_ensure_users_dot_netrc_Files_are_not_group_or_world_accessible_scored() {

}

6_2_14_ensure_no_users_have_dot_rhosts_files_scored() {

}

6_2_15_ensure_all_groups_in_etc_passwd_exist_in_etc_group_scored() {

}

6_2_16_ensure_no_duplicate_uids_exist_scored() {

}

6_2_17_ensure_no_duplicate_gids_exist_scored() {

}

6_2_18_ensure_no_duplicate_user_names_exist_scored() {

}

6_2_19_ensure_no_duplicate_group_names_exist_scored() {

}

6_2_20_ensure_shadow_group_is_empty_scored() {

}

main
