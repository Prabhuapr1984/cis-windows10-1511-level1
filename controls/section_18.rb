# encoding: UTF-8

control "xccdf_org.cisecurity.benchmarks_rule_18.1.1.1_L1_Ensure_Prevent_enabling_lock_screen_camera_is_set_to_Enabled" do
  title "(L1) Ensure 'Prevent enabling lock screen camera' is set to 'Enabled'"
  desc  "
    Disables the lock screen camera toggle switch in PC Settings and prevents a camera from being invoked on the lock screen.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Disabling the lock screen camera extends the protection afforded by the lock screen to camera features.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Personalization") do
    it { should have_property "NoLockScreenCamera" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Personalization") do
    its("NoLockScreenCamera") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.1.1.2_L1_Ensure_Prevent_enabling_lock_screen_slide_show_is_set_to_Enabled" do
  title "(L1) Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'"
  desc  "
    Disables the lock screen slide show settings in PC Settings and prevents a slide show from playing on the lock screen.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Disabling the lock screen slide show extends the protection afforded by the lock screen to slide show contents.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Personalization") do
    it { should have_property "NoLockScreenSlideshow" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Personalization") do
    its("NoLockScreenSlideshow") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.1.2.1_L1_Ensure_Allow_Input_Personalization_is_set_to_Disabled" do
  title "(L1) Ensure 'Allow Input Personalization' is set to 'Disabled'"
  desc  "
    This policy enables the automatic learning component of input personalization that includes speech, inking, and typing. Automatic learning enables the collection of speech and handwriting patterns, typing history, contacts, and recent calendar information. It is required for the use of Cortana. Some of this collected information may be stored on the user's OneDrive, in the case of inking and typing; some of the information will be uploaded to Microsoft to personalize speech.
    
    The recommended state for this setting is: Disabled
    
    Rationale: If this setting is Enabled sensitive information could be stored in the cloud or sent to Microsoft.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\InputPersonalization") do
    it { should have_property "AllowInputPersonalization" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\InputPersonalization") do
    its("AllowInputPersonalization") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.2.1_L1_Ensure_LAPS_AdmPwd_GPO_Extension__CSE_is_installed" do
  title "(L1) Ensure LAPS AdmPwd GPO Extension / CSE is installed"
  desc  "
    In May 2015, Microsoft released the Local Administrator Password Solution (LAPS) tool, which is free and supported software that allows an organization to automatically set randomized and unique local Administrator account passwords on domain-attached workstations and member servers. The passwords are stored in a confidential attribute of the domain computer account and can be retrieved from Active Directory by approved Sysadmins when needed.
    
    The LAPS tool requires a small Active Directory Schema update in order to implement, as well as installation of a Group Policy Client Side Extension (CSE) on targeted computers. Please see the LAPS documentation for details.
    
    LAPS supports Windows Vista or newer workstation OSes, and Server 2003 or newer server OSes. LAPS does not support standalone computers - they must be joined to a domain.
    
    **Note:** Organizations that utilize 3rd-party commercial software to manage unique  complex local Administrator passwords on domain members may opt to disregard these LAPS recommendations.
    
    Rationale: Due to the difficulty in managing local Administrator passwords, many organizations choose to use the same password on all workstations and/or member servers when deploying them. This poses a serious attack surface security risk because if an attacker manages to compromise one system and learn the password to its local Administrator account, then they can leverage that account to instantly gain access to all other computers that also use that password for their local Administrator account.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\GPExtensions\\{D76B9641-3288-4f75-942D-087DE603E3EA}") do
    it { should have_property "DllName" }
  end
  describe package('Local Administrator Password Solution') do
    it { should be_installed }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.2.2_L1_Ensure_Do_not_allow_password_expiration_time_longer_than_required_by_policy_is_set_to_Enabled" do
  title "(L1) Ensure 'Do not allow password expiration time longer than required by policy' is set to 'Enabled'"
  desc  "
    In May 2015, Microsoft released the Local Administrator Password Solution (LAPS) tool, which is free and supported software that allows an organization to automatically set randomized and unique local Administrator account passwords on domain-attached workstations and member servers. The passwords are stored in a confidential attribute of the domain computer account and can be retrieved from Active Directory by approved Sysadmins when needed.
    
    The LAPS tool requires a small Active Directory Schema update in order to implement, as well as installation of a Group Policy Client Side Extension (CSE) on targeted computers. Please see the LAPS documentation for details.
    
    LAPS supports Windows Vista or newer workstation OSes, and Server 2003 or newer server OSes. LAPS does not support standalone computers - they must be joined to a domain.
    
    The recommended state for this setting is: Enabled.
    
    **Note:** Organizations that utilize 3rd-party commercial software to manage unique  complex local Administrator passwords on domain members may opt to disregard these LAPS recommendations.
    
    Rationale: Due to the difficulty in managing local Administrator passwords, many organizations choose to use the same password on all workstations and/or member servers when deploying them. This poses a serious attack surface security risk because if an attacker manages to compromise one system and learn the password to its local Administrator account, then they can leverage that account to instantly gain access to all other computers that also use that password for their local Administrator account.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd") do
    it { should have_property "PwdExpirationProtectionEnabled" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd") do
    its("PwdExpirationProtectionEnabled") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.2.3_L1_Ensure_Enable_Local_Admin_Password_Management_is_set_to_Enabled" do
  title "(L1) Ensure 'Enable Local Admin Password Management' is set to 'Enabled'"
  desc  "
    In May 2015, Microsoft released the Local Administrator Password Solution (LAPS) tool, which is free and supported software that allows an organization to automatically set randomized and unique local Administrator account passwords on domain-attached workstations and member servers. The passwords are stored in a confidential attribute of the domain computer account and can be retrieved from Active Directory by approved Sysadmins when needed.
    
    The LAPS tool requires a small Active Directory Schema update in order to implement, as well as installation of a Group Policy Client Side Extension (CSE) on targeted computers. Please see the LAPS documentation for details.
    
    LAPS supports Windows Vista or newer workstation OSes, and Server 2003 or newer server OSes. LAPS does not support standalone computers - they must be joined to a domain.
    
    The recommended state for this setting is: Enabled.
    
    **Note:** Organizations that utilize 3rd-party commercial software to manage unique  complex local Administrator passwords on domain members may opt to disregard these LAPS recommendations.
    
    Rationale: Due to the difficulty in managing local Administrator passwords, many organizations choose to use the same password on all workstations and/or member servers when deploying them. This poses a serious attack surface security risk because if an attacker manages to compromise one system and learn the password to its local Administrator account, then they can leverage that account to instantly gain access to all other computers that also use that password for their local Administrator account.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd") do
    it { should have_property "AdmPwdEnabled" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd") do
    its("AdmPwdEnabled") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.2.4_L1_Ensure_Password_Settings_Password_Complexity_is_set_to_Enabled_Large_letters__small_letters__numbers__special_characters" do
  title "(L1) Ensure 'Password Settings: Password Complexity' is set to 'Enabled: Large letters + small letters + numbers + special characters'"
  desc  "
    In May 2015, Microsoft released the Local Administrator Password Solution (LAPS) tool, which is free and supported software that allows an organization to automatically set randomized and unique local Administrator account passwords on domain-attached workstations and member servers. The passwords are stored in a confidential attribute of the domain computer account and can be retrieved from Active Directory by approved Sysadmins when needed.
    
    The LAPS tool requires a small Active Directory Schema update in order to implement, as well as installation of a Group Policy Client Side Extension (CSE) on targeted computers. Please see the LAPS documentation for details.
    
    LAPS supports Windows Vista or newer workstation OSes, and Server 2003 or newer server OSes. LAPS does not support standalone computers - they must be joined to a domain.
    
    The recommended state for this setting is: Enabled: Large letters + small letters + numbers + special characters.
    
    **Note:** Organizations that utilize 3rd-party commercial software to manage unique  complex local Administrator passwords on domain members may opt to disregard these LAPS recommendations.
    
    Rationale: Due to the difficulty in managing local Administrator passwords, many organizations choose to use the same password on all workstations and/or member servers when deploying them. This poses a serious attack surface security risk because if an attacker manages to compromise one system and learn the password to its local Administrator account, then they can leverage that account to instantly gain access to all other computers that also use that password for their local Administrator account.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd") do
    it { should have_property "PasswordComplexity" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd") do
    its("PasswordComplexity") { should cmp == 4 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.2.5_L1_Ensure_Password_Settings_Password_Length_is_set_to_Enabled_15_or_more" do
  title "(L1) Ensure 'Password Settings: Password Length' is set to 'Enabled: 15 or more'"
  desc  "
    In May 2015, Microsoft released the Local Administrator Password Solution (LAPS) tool, which is free and supported software that allows an organization to automatically set randomized and unique local Administrator account passwords on domain-attached workstations and member servers. The passwords are stored in a confidential attribute of the domain computer account and can be retrieved from Active Directory by approved Sysadmins when needed.
    
    The LAPS tool requires a small Active Directory Schema update in order to implement, as well as installation of a Group Policy Client Side Extension (CSE) on targeted computers. Please see the LAPS documentation for details.
    
    LAPS supports Windows Vista or newer workstation OSes, and Server 2003 or newer server OSes. LAPS does not support standalone computers - they must be joined to a domain.
    
    The recommended state for this setting is: Enabled: 15 or more.
    
    **Note:** Organizations that utilize 3rd-party commercial software to manage unique  complex local Administrator passwords on domain members may opt to disregard these LAPS recommendations.
    
    Rationale: Due to the difficulty in managing local Administrator passwords, many organizations choose to use the same password on all workstations and/or member servers when deploying them. This poses a serious attack surface security risk because if an attacker manages to compromise one system and learn the password to its local Administrator account, then they can leverage that account to instantly gain access to all other computers that also use that password for their local Administrator account.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd") do
    it { should have_property "PasswordLength" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd") do
    its("PasswordLength") { should cmp >= 15 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.2.6_L1_Ensure_Password_Settings_Password_Age_Days_is_set_to_Enabled_30_or_fewer" do
  title "(L1) Ensure 'Password Settings: Password Age (Days)' is set to 'Enabled: 30 or fewer'"
  desc  "
    In May 2015, Microsoft released the Local Administrator Password Solution (LAPS) tool, which is free and supported software that allows an organization to automatically set randomized and unique local Administrator account passwords on domain-attached workstations and member servers. The passwords are stored in a confidential attribute of the domain computer account and can be retrieved from Active Directory by approved Sysadmins when needed.
    
    The LAPS tool requires a small Active Directory Schema update in order to implement, as well as installation of a Group Policy Client Side Extension (CSE) on targeted computers. Please see the LAPS documentation for details.
    
    LAPS supports Windows Vista or newer workstation OSes, and Server 2003 or newer server OSes. LAPS does not support standalone computers - they must be joined to a domain.
    
    The recommended state for this setting is: Enabled: 30 or fewer.
    
    **Note:** Organizations that utilize 3rd-party commercial software to manage unique  complex local Administrator passwords on domain members may opt to disregard these LAPS recommendations.
    
    Rationale: Due to the difficulty in managing local Administrator passwords, many organizations choose to use the same password on all workstations and/or member servers when deploying them. This poses a serious attack surface security risk because if an attacker manages to compromise one system and learn the password to its local Administrator account, then they can leverage that account to instantly gain access to all other computers that also use that password for their local Administrator account.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd") do
    it { should have_property "PasswordAgeDays" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd") do
    its("PasswordAgeDays") { should cmp <= 30 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.3.1_L1_Ensure_MSS_AutoAdminLogon_Enable_Automatic_Logon_not_recommended_is_set_to_Disabled" do
  title "(L1) Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' is set to 'Disabled'"
  desc  "
    This setting is separate from the Welcome screen feature in Windows XP and Windows Vista; if that feature is disabled, this setting is not disabled. If you configure a computer for automatic logon, anyone who can physically gain access to the computer can also gain access to everything that is on the computer, including any network or networks to which the computer is connected. Also, if you enable automatic logon, the password is stored in the registry in plaintext, and the specific registry key that stores this value is remotely readable by the Authenticated Users group.
    
    For additional information, see Microsoft Knowledge Base article 324737: [How to turn on automatic logon in Windows](https://support.microsoft.com/en-us/kb/324737).
    
    The recommended state for this setting is: Disabled.
    
    Rationale: If you configure a computer for automatic logon, anyone who can physically gain access to the computer can also gain access to everything that is on the computer, including any network or networks that the computer is connected to. Also, if you enable automatic logon, the password is stored in the registry in plaintext. The specific registry key that stores this setting is remotely readable by the Authenticated Users group. As a result, this entry is appropriate only if the computer is physically secured and if you ensure that untrusted users cannot remotely see the registry.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon") do
    it { should have_property "AutoAdminLogon" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon") do
    its("AutoAdminLogon") { should eq "0" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.3.2_L1_Ensure_MSS_DisableIPSourceRouting_IPv6_IP_source_routing_protection_level_protects_against_packet_spoofing_is_set_to_Enabled_Highest_protection_source_routing_is_completely_disabled" do
  title "(L1) Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'"
  desc  "
    IP source routing is a mechanism that allows the sender to determine the IP route that a datagram should follow through the network.
    
    The recommended state for this setting is: Enabled: Highest protection, source routing is completely disabled.
    
    Rationale: An attacker could use source routed packets to obscure their identity and location. Source routing allows a computer that sends a packet to specify the route that the packet takes.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip6\\Parameters") do
    it { should have_property "DisableIPSourceRouting" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip6\\Parameters") do
    its("DisableIPSourceRouting") { should cmp == 2 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.3.3_L1_Ensure_MSS_DisableIPSourceRouting_IP_source_routing_protection_level_protects_against_packet_spoofing_is_set_to_Enabled_Highest_protection_source_routing_is_completely_disabled" do
  title "(L1) Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'"
  desc  "
    IP source routing is a mechanism that allows the sender to determine the IP route that a datagram should take through the network. It is recommended to configure this setting to Not Defined for enterprise environments and to Highest Protection for high security environments to completely disable source routing.
    
    The recommended state for this setting is: Enabled: Highest protection, source routing is completely disabled.
    
    Rationale: An attacker could use source routed packets to obscure their identity and location. Source routing allows a computer that sends a packet to specify the route that the packet takes.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters") do
    it { should have_property "DisableIPSourceRouting" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters") do
    its("DisableIPSourceRouting") { should cmp == 2 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.3.5_L1_Ensure_MSS_EnableICMPRedirect_Allow_ICMP_redirects_to_override_OSPF_generated_routes_is_set_to_Disabled" do
  title "(L1) Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'"
  desc  "
    Internet Control Message Protocol (ICMP) redirects cause the IPv4 stack to plumb host routes. These routes override the Open Shortest Path First (OSPF) generated routes.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: This behavior is expected. The problem is that the 10 minute time-out period for the ICMP redirect-plumbed routes temporarily creates a network situation in which traffic will no longer be routed properly for the affected host. Ignoring such ICMP redirects will limit the system's exposure to attacks that will impact its ability to participate on the network.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters") do
    it { should have_property "EnableICMPRedirect" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters") do
    its("EnableICMPRedirect") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.3.7_L1_Ensure_MSS_NoNameReleaseOnDemand_Allow_the_computer_to_ignore_NetBIOS_name_release_requests_except_from_WINS_servers_is_set_to_Enabled" do
  title "(L1) Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled'"
  desc  "
    NetBIOS over TCP/IP is a network protocol that among other things provides a way to easily resolve NetBIOS names that are registered on Windows-based systems to the IP addresses that are configured on those systems. This setting determines whether the computer releases its NetBIOS name when it receives a name-release request.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: The NetBT protocol is designed not to use authentication, and is therefore vulnerable to spoofing. Spoofing makes a transmission appear to come from a user other than the user who performed the action. A malicious user could exploit the unauthenticated nature of the protocol to send a name-conflict datagram to a target computer, which would cause the computer to relinquish its name and not respond to queries.
    
    The result of such an attack could be to cause intermittent connectivity issues on the target computer, or even to prevent the use of Network Neighborhood, domain logons, the NET SEND command, or additional NetBIOS name resolution.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\NetBT\\Parameters") do
    it { should have_property "nonamereleaseondemand" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\NetBT\\Parameters") do
    its("nonamereleaseondemand") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.3.9_L1_Ensure_MSS_SafeDllSearchMode_Enable_Safe_DLL_search_mode_recommended_is_set_to_Enabled" do
  title "(L1) Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)' is set to 'Enabled'"
  desc  "
    The DLL search order can be configured to search for DLLs that are requested by running processes in one of two ways:
    
    * Search folders specified in the system path first, and then search the current working folder.
    * Search current working folder first, and then search the folders specified in the system path.
    When enabled, the registry value is set to 1. With a setting of 1, the system first searches the folders that are specified in the system path and then searches the current working folder. When disabled the registry value is set to 0 and the system first searches the current working folder and then searches the folders that are specified in the system path.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: If a user unknowingly executes hostile code that was packaged with additional files that include modified versions of system DLLs, the hostile code could load its own versions of those DLLs and potentially increase the type and degree of damage the code can render.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager") do
    it { should have_property "SafeDllSearchMode" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager") do
    its("SafeDllSearchMode") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.3.10_L1_Ensure_MSS_ScreenSaverGracePeriod_The_time_in_seconds_before_the_screen_saver_grace_period_expires_0_recommended_is_set_to_Enabled_5_or_fewer_seconds" do
  title "(L1) Ensure 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)' is set to 'Enabled: 5 or fewer seconds'"
  desc  "
    Windows includes a grace period between when the screen saver is launched and when the console is actually locked automatically when screen saver locking is enabled.
    
    The recommended state for this setting is: Enabled: 5 or fewer seconds.
    
    Rationale: The default grace period that is allowed for user movement before the screen saver lock takes effect is five seconds. If you leave the default grace period configuration, your computer is vulnerable to a potential attack from someone who could approach the console and attempt to log on to the computer before the lock takes effect. An entry to the registry can be made to adjust the length of the grace period.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon") do
    it { should have_property "ScreenSaverGracePeriod" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon") do
    its("ScreenSaverGracePeriod") { should cmp <= 5 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.3.13_L1_Ensure_MSS_WarningLevel_Percentage_threshold_for_the_security_event_log_at_which_the_system_will_generate_a_warning_is_set_to_Enabled_90_or_less" do
  title "(L1) Ensure 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less'"
  desc  "
    This setting can generate a security audit in the Security event log when the log reaches a user-defined threshold.
    
    **Note:** If log settings are configured to Overwrite events as needed or Overwrite events older than x days, this event will not be generated.
    
    The recommended state for this setting is: Enabled: 90% or less.
    
    Rationale: If the Security log reaches 90 percent of its capacity and the computer has not been configured to overwrite events as needed, more recent events will not be written to the log. If the log reaches its capacity and the computer has been configured to shut down when it can no longer record events to the Security log, the computer will shut down and will no longer be available to provide network services.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Eventlog\\Security") do
    it { should have_property "WarningLevel" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Eventlog\\Security") do
    its("WarningLevel") { should cmp <= 90 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.4.7.1_L1_Ensure_Enable_insecure_guest_logons_is_set_to_Disabled" do
  title "(L1) Ensure 'Enable insecure guest logons' is set to 'Disabled'"
  desc  "
    This policy setting determines if the SMB client will allow insecure guest logons to an SMB server.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Insecure guest logons are used by file servers to allow unauthenticated access to shared folders.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\LanmanWorkstation") do
    it { should have_property "AllowInsecureGuestAuth" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\LanmanWorkstation") do
    its("AllowInsecureGuestAuth") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.4.10.2_L1_Ensure_Prohibit_installation_and_configuration_of_Network_Bridge_on_your_DNS_domain_network_is_set_to_Enabled" do
  title "(L1) Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'"
  desc  "
    You can use this procedure to enable or disable the user's ability to install and configure a network bridge.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Allowing users to create a network bridge increases the risk and attack surface from the bridged network.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Network Connections") do
    it { should have_property "NC_AllowNetBridge_NLA" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Network Connections") do
    its("NC_AllowNetBridge_NLA") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.4.10.3_L1_Ensure_Require_domain_users_to_elevate_when_setting_a_networks_location_is_set_to_Enabled" do
  title "(L1) Ensure 'Require domain users to elevate when setting a network's location' is set to 'Enabled'"
  desc  "
    This policy setting determines whether to require domain users to elevate when setting a network's location.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Allowing regular users to set a network location increases the risk and attack surface.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Network Connections") do
    it { should have_property "NC_StdDomainUserSetLocation" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Network Connections") do
    its("NC_StdDomainUserSetLocation") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.4.13.1_L1_Ensure_Hardened_UNC_Paths_is_set_to_Enabled_with_Require_Mutual_Authentication_and_Require_Integrity_set_for_all_NETLOGON_and_SYSVOL_shares" do
  title "(L1) Ensure 'Hardened UNC Paths' is set to 'Enabled, with \"Require Mutual Authentication\" and \"Require Integrity\" set for all NETLOGON and SYSVOL shares'"
  desc  "
    This policy setting configures secure access to UNC paths.
    
    The recommended state for this setting is: Enabled, with \"Require Mutual Authentication\" and \"Require Integrity\" set for all NETLOGON and SYSVOL shares.
    
    **Note:** If the environment exclusively contains Windows 8.0 / Server 2012 or higher systems, then the \"Privacy\" setting may (optionally) also be set to enable SMB encryption. However, using SMB encryption will render the targeted share paths completely inaccessible by older OSes, so only use this additional option with caution and thorough testing.
    
    Rationale: In February 2015, Microsoft released a new control mechanism to mitigate a security risk in Group Policy as part of [MS15-011](https://technet.microsoft.com/library/security/MS15-011) / [MSKB 3000483](https://support.microsoft.com/en-us/kb/3000483). This mechanism requires both the installation of the new security update and also the deployment of specific group policy settings to all computers on the domain from Vista/Server 2008 or higher (the associated security patch to enable this feature was not released for Server 2003). A new group policy template (NetworkProvider.admx/adml) was also provided with the security update.
    
    Once the new GPO template is in place, the following are the minimum requirements to remediate the Group Policy security risk:
    \\\\*\\NETLOGON RequireMutualAuthentication=1, RequireIntegrity=1
    \\\\*\\SYSVOL RequireMutualAuthentication=1, RequireIntegrity=1
    
    **Note:** A reboot may be required after the setting is applied to a client machine to access the above paths.
    
    Additional guidance on the deployment of this security setting is available from the Microsoft Premier Field Engineering (PFE) Platforms TechNet Blog here: [Guidance on Deployment of MS15-011 and MS15-014](http://blogs.technet.com/b/askpfeplat/archive/2015/02/23/guidance-on-deployment-of-ms15-011-and-ms15-014.aspx).
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths") do
    it { should have_property "\\\\*\\NETLOGON" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths") do
    its("\\\\*\\NETLOGON") { should match(//) }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths") do
    it { should have_property "\\\\*\\SYSVOL" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths") do
    its("\\\\*\\SYSVOL") { should match(//) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.4.20.1_L1_Ensure_Minimize_the_number_of_simultaneous_connections_to_the_Internet_or_a_Windows_Domain_is_set_to_Enabled" do
  title "(L1) Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled'"
  desc  "
    This policy setting prevents computers from establishing multiple simultaneous connections to either the Internet or to a Windows domain.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Blocking simultaneous connections can help prevent a user unknowingly allowing network traffic to flow between the Internet and the corporate network.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WcmSvc\\GroupPolicy") do
    it { should have_property "fMinimizeConnections" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WcmSvc\\GroupPolicy") do
    its("fMinimizeConnections") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.4.20.2_L1_Ensure_Prohibit_connection_to_non-domain_networks_when_connected_to_domain_authenticated_network_is_set_to_Enabled" do
  title "(L1) Ensure 'Prohibit connection to non-domain networks when connected to domain authenticated network' is set to 'Enabled'"
  desc  "
    This policy setting prevents computers from connecting to both a domain based network and a non-domain based network at the same time.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: The potential concern is that a user would unknowingly allow network traffic to flow between the insecure public network and the managed corporate network.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WcmSvc\\GroupPolicy") do
    it { should have_property "fBlockNonDomain" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WcmSvc\\GroupPolicy") do
    its("fBlockNonDomain") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.4.22.2.1_L1_Ensure_Allow_Windows_to_automatically_connect_to_suggested_open_hotspots_to_networks_shared_by_contacts_and_to_hotspots_offering_paid_services_is_set_to_Disabled" do
  title "(L1) Ensure 'Allow Windows to automatically connect to suggested open hotspots, to networks shared by contacts, and to hotspots offering paid services' is set to 'Disabled'"
  desc  "
    This policy setting determines whether users can enable the following WLAN settings: \"Connect to suggested open hotspots,\" \"Connect to networks shared by my contacts,\" and \"Enable paid services\".
    
    \"Connect to suggested open hotspots\" enables Windows to automatically connect users to open hotspots it knows about by crowdsourcing networks that other people using Windows have connected to.
    
    \"Connect to networks shared by my contacts\" enables Windows to automatically connect to networks that the user's contacts have shared with them, and enables users on this device to share networks with their contacts.
    
    \"Enable paid services\" enables Windows to temporarily connect to open hotspots to determine if paid services are available.
    
    The recommended state for this setting is: Disabled.
    
    **Note:** These features are also known by the name \"**Wi-Fi Sense**\".
    
    Rationale: Automatically connecting to an open hotspot or network can introduce the system to a rogue network with malicious intent.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\WcmSvc\\wifinetworkmanager\\config") do
    it { should have_property "AutoConnectAllowedOEM" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\WcmSvc\\wifinetworkmanager\\config") do
    its("AutoConnectAllowedOEM") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.6.1_L1_Ensure_Apply_UAC_restrictions_to_local_accounts_on_network_logons_is_set_to_Enabled" do
  title "(L1) Ensure 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled'"
  desc  "
    This setting controls whether local accounts can be used for remote administration via network logon (e.g., NET USE, connecting to C$, etc.). Local accounts are at high risk for credential theft when the same account and password is configured on multiple systems. Enabling this policy significantly reduces that risk.
    
    **Enabled:** Applies UAC token-filtering to local accounts on network logons. Membership in powerful group such as Administrators is disabled and powerful privileges are removed from the resulting access token. This configures the LocalAccountTokenFilterPolicy registry value to 0. This is the default behavior for Windows.
    
    **Disabled:** Allows local accounts to have full administrative rights when authenticating via network logon, by configuring the LocalAccountTokenFilterPolicy registry value to 1.
    
    For more information about local accounts and credential theft, review the \"[Mitigating Pass-the-Hash (PtH) Attacks and Other Credential Theft Techniques](http://www.microsoft.com/en-us/download/details.aspx?id=36036)\" documents.
    
    For more information about LocalAccountTokenFilterPolicy, see Microsoft Knowledge Base article 951016: [Description of User Account Control and remote restrictions in Windows Vista](https://support.microsoft.com/en-us/kb/951016).
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Local accounts are at high risk for credential theft when the same account and password is configured on multiple systems. Ensuring this policy is Enabled significantly reduces that risk.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
    it { should have_property "LocalAccountTokenFilterPolicy" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
    its("LocalAccountTokenFilterPolicy") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.6.2_L1_Ensure_WDigest_Authentication_is_set_to_Disabled" do
  title "(L1) Ensure 'WDigest Authentication' is set to 'Disabled'"
  desc  "
    When WDigest authentication is enabled, Lsass.exe retains a copy of the user's plaintext password in memory, where it can be at risk of theft. If this setting is not configured, WDigest authentication is disabled in Windows 8.1 and in Windows Server 2012 R2; it is enabled by default in earlier versions of Windows and Windows Server.
    
    For more information about local accounts and credential theft, review the \"[Mitigating Pass-the-Hash (PtH) Attacks and Other Credential Theft Techniques](http://www.microsoft.com/en-us/download/details.aspx?id=36036)\" documents.
    
    For more information about UseLogonCredential, see Microsoft Knowledge Base article 2871997: [Microsoft Security Advisory Update to improve credentials protection and management May 13, 2014](https://support.microsoft.com/en-us/kb/2871997).
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Preventing the plaintext storage of credentials in memory may reduce opportunity for credential theft.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest") do
    it { should have_property "UseLogonCredential" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest") do
    its("UseLogonCredential") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.2.1_L1_Ensure_Include_command_line_in_process_creation_events_is_set_to_Disabled" do
  title "(L1) Ensure 'Include command line in process creation events' is set to 'Disabled'"
  desc  "
    This policy setting determines what information is logged in security audit events when a new process has been created.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: When this policy setting is enabled, any user who has read access to the security events can read the command-line arguments for any successfully created process. Command-line arguments may contain sensitive or private information such as passwords or user data.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit") do
    it { should have_property "ProcessCreationIncludeCmdLine_Enabled" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit") do
    its("ProcessCreationIncludeCmdLine_Enabled") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.11.1_L1_Ensure_Boot-Start_Driver_Initialization_Policy_is_set_to_Enabled_Good_unknown_and_bad_but_critical" do
  title "(L1) Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'"
  desc  "
    This policy setting allows you to specify which boot-start drivers are initialized based on a classification determined by an Early Launch Antimalware boot-start driver. The Early Launch Antimalware boot-start driver can return the following classifications for each boot-start driver:
    
    * Good: The driver has been signed and has not been tampered with.
    * Bad: The driver has been identified as malware. It is recommended that you do not allow known bad drivers to be initialized.
    * Bad, but required for boot: The driver has been identified as malware, but the computer cannot successfully boot without loading this driver.
    * Unknown: This driver has not been attested to by your malware detection application and has not been classified by the Early Launch Antimalware boot-start driver.
    If you enable this policy setting you will be able to choose which boot-start drivers to initialize the next time the computer is started.
    
    If you disable or do not configure this policy setting, the boot start drivers determined to be Good, Unknown or Bad but Boot Critical are initialized and the initialization of drivers determined to be Bad is skipped.
    
    If your malware detection application does not include an Early Launch Antimalware boot-start driver or if your Early Launch Antimalware boot-start driver has been disabled, this setting has no effect and all boot-start drivers are initialized.
    
    The recommended state for this setting is: Enabled: Good, unknown and bad but critical.
    
    Rationale: This policy setting helps reduce the impact of malware that has already infected your system.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Policies\\EarlyLaunch") do
    it { should have_property "DriverLoadPolicy" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Policies\\EarlyLaunch") do
    its("DriverLoadPolicy") { should cmp == 3 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.18.2_L1_Ensure_Configure_registry_policy_processing_Do_not_apply_during_periodic_background_processing_is_set_to_Enabled_FALSE" do
  title "(L1) Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'"
  desc  "
    The \"Do not apply during periodic background processing\" option prevents the system from updating affected policies in the background while the computer is in use. When background updates are disabled, policy changes will not take effect until the next user logon or system restart.
    
    The recommended state for this setting is: Enabled: FALSE (unchecked).
    
    Rationale: Setting this option to false (unchecked) will ensure that domain policy changes take effect more quickly, as compared to waiting until the next user logon or system restart.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Group Policy\\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}") do
    it { should have_property "NoBackgroundPolicy" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Group Policy\\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}") do
    its("NoBackgroundPolicy") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.18.3_L1_Ensure_Configure_registry_policy_processing_Process_even_if_the_Group_Policy_objects_have_not_changed_is_set_to_Enabled_TRUE" do
  title "(L1) Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'"
  desc  "
    The \"Process even if the Group Policy objects have not changed\" option updates and reapplies policies even if the policies have not changed.
    
    The recommended state for this setting is: Enabled: TRUE (checked).
    
    Rationale: Setting this option to true (checked) will ensure unauthorized changes that might have been configured locally are forced to match the domain-based Group Policy settings again.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Group Policy\\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}") do
    it { should have_property "NoGPOListChanges" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Group Policy\\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}") do
    its("NoGPOListChanges") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.18.4_L1_Ensure_Turn_off_background_refresh_of_Group_Policy_is_set_to_Disabled" do
  title "(L1) Ensure 'Turn off background refresh of Group Policy' is set to 'Disabled'"
  desc  "
    This policy setting prevents Group Policy from being updated while the computer is in use. This policy setting applies to Group Policy for computers, users and domain controllers.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Setting this option to false (unchecked) will ensure that group policy changes take effect more quickly, as compared to waiting until the next user logon or system restart.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
    it { should_not have_property "DisableBkGndGroupPolicy" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.24.1_L1_Ensure_Do_not_display_network_selection_UI_is_set_to_Enabled" do
  title "(L1) Ensure 'Do not display network selection UI' is set to 'Enabled'"
  desc  "
    This policy setting allows you to control whether anyone can interact with available networks UI on the logon screen.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: An unauthorized user could disconnect the PC from the network or can connect the PC to other available networks without signing into Windows.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System") do
    it { should have_property "DontDisplayNetworkSelectionUI" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System") do
    its("DontDisplayNetworkSelectionUI") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.24.2_L1_Ensure_Do_not_enumerate_connected_users_on_domain-joined_computers_is_set_to_Enabled" do
  title "(L1) Ensure 'Do not enumerate connected users on domain-joined computers' is set to 'Enabled'"
  desc  "
    This policy setting prevents connected users from being enumerated on domain-joined computers.
    
    If you enable this policy setting, the Logon UI will not enumerate any connected users on domain-joined computers.
    
    If you disable or do not configure this policy setting, connected users will be enumerated on domain-joined computers.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: A malicious user could use this feature to gather account names of other users, that information could then be used in conjunction with other types of attacks such as guessing passwords or social engineering. The value of this countermeasure is small because a user with domain credentials could gather the same account information using other methods.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System") do
    it { should have_property "DontEnumerateConnectedUsers" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System") do
    its("DontEnumerateConnectedUsers") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.24.3_L1_Ensure_Enumerate_local_users_on_domain-joined_computers_is_set_to_Disabled" do
  title "(L1) Ensure 'Enumerate local users on domain-joined computers' is set to 'Disabled'"
  desc  "
    This policy setting allows local users to be enumerated on domain-joined computers.
    
    If you enable this policy setting, Logon UI will enumerate all local users on domain-joined computers.
    
    If you disable or do not configure this policy setting, the Logon UI will not enumerate local users on domain-joined computers.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: A malicious user could use this feature to gather account names of other users, that information could then be used in conjunction with other types of attacks such as guessing passwords or social engineering. The value of this countermeasure is small because a user with domain credentials could gather the same account information using other methods.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System") do
    it { should have_property "EnumerateLocalUsers" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System") do
    its("EnumerateLocalUsers") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.24.4_L1_Ensure_Turn_off_app_notifications_on_the_lock_screen_is_set_to_Enabled" do
  title "(L1) Ensure 'Turn off app notifications on the lock screen' is set to 'Enabled'"
  desc  "
    This policy setting allows you to prevent app notifications from appearing on the lock screen.
    
    If you enable this policy setting, no app notifications are displayed on the lock screen.
    
    If you disable or do not configure this policy setting, users can choose which apps display notifications on the lock screen.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: App notifications might display sensitive business or personal data.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System") do
    it { should have_property "DisableLockScreenAppNotifications" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System") do
    its("DisableLockScreenAppNotifications") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.24.5_L1_Ensure_Turn_on_convenience_PIN_sign-in_is_set_to_Disabled" do
  title "(L1) Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled'"
  desc  "
    This policy setting allows you to control whether a domain user can sign in using a convenience PIN. In Windows 10, convenience PIN was replaced with Passport, which has stronger security properties. To configure Passport for domain users, use the policies under Computer configuration\\Administrative Templates\\Windows Components\\Microsoft Passport for Work.
    
    If you enable this policy setting, a domain user can set up and sign in with a convenience PIN.
    
    If you disable or don't configure this policy setting, a domain user can't set up and use a convenience PIN.
    
    Note that the user's domain password will be cached in the system vault when using this feature.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: A PIN is created from a much smaller selection of characters than a password, so in most cases a PIN will be much less robust than a password.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System") do
    it { should have_property "AllowDomainPINLogon" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System") do
    its("AllowDomainPINLogon") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.25.1_L1_Ensure_Untrusted_Font_Blocking_is_set_to_Enabled_Block_untrusted_fonts_and_log_events" do
  title "(L1) Ensure 'Untrusted Font Blocking' is set to 'Enabled: Block untrusted fonts and log events'"
  desc  "
    This security feature provides a global setting to prevent programs from loading untrusted fonts. Untrusted fonts are any font installed outside of the %windir%\\Fonts directory. This feature can be configured to be in 3 modes: On, Off, and Audit.
    
    The recommended state for this setting is: Enabled: Block untrusted fonts and log events
    
    Rationale: Blocking untrusted fonts helps prevent both remote (web-based or email-based) and local EOP attacks that can happen during the font file-parsing process.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\MitigationOptions") do
    it { should have_property "MitigationOptions_FontBocking" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\MitigationOptions") do
    its("MitigationOptions_FontBocking") { should eq "1000000000000" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.28.4.3_L1_Ensure_Require_a_password_when_a_computer_wakes_on_battery_is_set_to_Enabled" do
  title "(L1) Ensure 'Require a password when a computer wakes (on battery)' is set to 'Enabled'"
  desc  "
    Specifies whether or not the user is prompted for a password when the system resumes from sleep.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Enabling this setting ensures that anyone who wakes an unattended computer from sleep state will have to provide logon credentials before they can access the system.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51") do
    it { should have_property "DCSettingIndex" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51") do
    its("DCSettingIndex") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.28.4.4_L1_Ensure_Require_a_password_when_a_computer_wakes_plugged_in_is_set_to_Enabled" do
  title "(L1) Ensure 'Require a password when a computer wakes (plugged in)' is set to 'Enabled'"
  desc  "
    Specifies whether or not the user is prompted for a password when the system resumes from sleep.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Enabling this setting ensures that anyone who wakes an unattended computer from sleep state will have to provide logon credentials before they can access the system.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51") do
    it { should have_property "ACSettingIndex" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51") do
    its("ACSettingIndex") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.30.1_L1_Ensure_Configure_Offer_Remote_Assistance_is_set_to_Disabled" do
  title "(L1) Ensure 'Configure Offer Remote Assistance' is set to 'Disabled'"
  desc  "
    This policy setting allows you to turn on or turn off Offer (Unsolicited) Remote Assistance on this computer.
    
    If you enable this policy setting, users on this computer can get help from their corporate technical support staff using Offer (Unsolicited) Remote Assistance.
    
    If you disable this policy setting, users on this computer cannot get help from their corporate technical support staff using Offer (Unsolicited) Remote Assistance.
    
    If you do not configure this policy setting, users on this computer cannot get help from their corporate technical support staff using Offer (Unsolicited) Remote Assistance.
    
    If you enable this policy setting, you have two ways to allow helpers to provide Remote Assistance: \"Allow helpers to only view the computer\" or \"Allow helpers to remotely control the computer.\" When you configure this policy setting, you also specify the list of users or user groups that are allowed to offer remote assistance.
    
    To configure the list of helpers, click \"Show.\" In the window that opens, you can enter the names of the helpers. Add each user or group one by one. When you enter the name of the helper user or user groups, use the following format:
    
    <Domain>\\<User> or
    <Domain>\\<Group>
    
    If you enable this policy setting, you should also enable firewall exceptions to allow Remote Assistance communications. The firewall exceptions required for Offer (Unsolicited) Remote Assistance depend on the version of Windows you are running:
    
    Windows Vista and later:
    Enable the Remote Assistance exception for the domain profile. The exception must contain:
    Port 135:TCP
    %WINDIR%\\System32\\msra.exe
    %WINDIR%\\System32\\raserver.exe
    
    Windows XP with Service Pack 2 (SP2) and Windows XP Professional x64 Edition with Service Pack 1 (SP1):
    Port 135:TCP
    %WINDIR%\\PCHealth\\HelpCtr\\Binaries\\Helpsvc.exe
    %WINDIR%\\PCHealth\\HelpCtr\\Binaries\\Helpctr.exe
    %WINDIR%\\System32\\Sessmgr.exe
    
    For computers running Windows Server 2003 with Service Pack 1 (SP1)
    Port 135:TCP
    %WINDIR%\\PCHealth\\HelpCtr\\Binaries\\Helpsvc.exe
    %WINDIR%\\PCHealth\\HelpCtr\\Binaries\\Helpctr.exe
    Allow Remote Desktop Exception
    
    The recommended state for this setting is: Disabled.</Group></Domain></User></Domain>
    
    Rationale: A user might be tricked and accept an unsolicited Remote Assistance offer from a malicious user.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\policies\\Microsoft\\Windows NT\\Terminal Services") do
    it { should have_property "fAllowUnsolicited" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\policies\\Microsoft\\Windows NT\\Terminal Services") do
    its("fAllowUnsolicited") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.30.2_L1_Ensure_Configure_Solicited_Remote_Assistance_is_set_to_Disabled" do
  title "(L1) Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'"
  desc  "
    This policy setting allows you to turn on or turn off Solicited (Ask for) Remote Assistance on this computer.
    
    If you enable this policy setting, users on this computer can use email or file transfer to ask someone for help. Also, users can use instant messaging programs to allow connections to this computer, and you can configure additional Remote Assistance settings.
    
    If you disable this policy setting, users on this computer cannot use email or file transfer to ask someone for help. Also, users cannot use instant messaging programs to allow connections to this computer.
    
    If you do not configure this policy setting, users can turn on or turn off Solicited (Ask for) Remote Assistance themselves in System Properties in Control Panel. Users can also configure Remote Assistance settings.
    
    If you enable this policy setting, you have two ways to allow helpers to provide Remote Assistance: \"Allow helpers to only view the computer\" or \"Allow helpers to remotely control the computer.\"
    
    The \"Maximum ticket time\" policy setting sets a limit on the amount of time that a Remote Assistance invitation created by using email or file transfer can remain open.
    
    The \"Select the method for sending email invitations\" setting specifies which email standard to use to send Remote Assistance invitations. Depending on your email program, you can use either the Mailto standard (the invitation recipient connects through an Internet link) or the SMAPI (Simple MAPI) standard (the invitation is attached to your email message). This policy setting is not available in Windows Vista since SMAPI is the only method supported.
    
    If you enable this policy setting you should also enable appropriate firewall exceptions to allow Remote Assistance communications.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: There is slight risk that a rogue administrator will gain access to another user's desktop session, however, they cannot connect to a user's computer unannounced or control it without permission from the user. When an expert tries to connect, the user can still choose to deny the connection or give the expert view-only privileges. The user must explicitly click the Yes button to allow the expert to remotely control the workstation.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\policies\\Microsoft\\Windows NT\\Terminal Services") do
    it { should have_property "fAllowToGetHelp" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\policies\\Microsoft\\Windows NT\\Terminal Services") do
    its("fAllowToGetHelp") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.31.1_L1_Ensure_Enable_RPC_Endpoint_Mapper_Client_Authentication_is_set_to_Enabled" do
  title "(L1) Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled'"
  desc  "
    This policy setting controls whether RPC clients authenticate with the Endpoint Mapper Service when the call they are making contains authentication information. The Endpoint Mapper Service on computers running Windows NT4 (all service packs) cannot process authentication information supplied in this manner.
    
    If you disable this policy setting, RPC clients will not authenticate to the Endpoint Mapper Service, but they will be able to communicate with the Endpoint Mapper Service on Windows NT4 Server.
    
    If you enable this policy setting, RPC clients will authenticate to the Endpoint Mapper Service for calls that contain authentication information. Clients making such calls will not be able to communicate with the Windows NT4 Server Endpoint Mapper Service.
    
    If you do not configure this policy setting, it remains disabled. RPC clients will not authenticate to the Endpoint Mapper Service, but they will be able to communicate with the Windows NT4 Server Endpoint Mapper Service.
    
    **Note:** This policy will not be applied until the system is rebooted.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Anonymous access to RPC services could result in accidental disclosure of information to unauthenticated users.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Rpc") do
    it { should have_property "EnableAuthEpResolution" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Rpc") do
    its("EnableAuthEpResolution") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.31.2_L1_Ensure_Restrict_Unauthenticated_RPC_clients_is_set_to_Enabled_Authenticated" do
  title "(L1) Ensure 'Restrict Unauthenticated RPC clients' is set to 'Enabled: Authenticated'"
  desc  "
    This policy setting controls how the RPC server runtime handles unauthenticated RPC clients connecting to RPC servers.
    
    This policy setting impacts all RPC applications. In a domain environment this policy setting should be used with caution as it can impact a wide range of functionality including group policy processing itself. Reverting a change to this policy setting can require manual intervention on each affected machine. **This policy setting should never be applied to a domain controller.**
    
    If you disable this policy setting, the RPC server runtime uses the value of \"Authenticated\" on Windows Client, and the value of \"None\" on Windows Server versions that support this policy setting.
    
    If you do not configure this policy setting, it remains disabled. The RPC server runtime will behave as though it was enabled with the value of \"Authenticated\" used for Windows Client and the value of \"None\" used for Server SKUs that support this policy setting.
    
    If you enable this policy setting, it directs the RPC server runtime to restrict unauthenticated RPC clients connecting to RPC servers running on a machine. A client will be considered an authenticated client if it uses a named pipe to communicate with the server or if it uses RPC Security. RPC Interfaces that have specifically requested to be accessible by unauthenticated clients may be exempt from this restriction, depending on the selected value for this policy setting.
    
    -- \"**None**\" allows all RPC clients to connect to RPC Servers running on the machine on which the policy setting is applied.
    -- \"**Authenticated**\" allows only authenticated RPC Clients (per the definition above) to connect to RPC Servers running on the machine on which the policy setting is applied. Exemptions are granted to interfaces that have requested them.
    -- \"**Authenticated without exceptions**\" allows only authenticated RPC Clients (per the definition above) to connect to RPC Servers running on the machine on which the policy setting is applied. No exceptions are allowed. **This value has the potential to cause serious problems and is not recommended.**
    
    **Note:** This policy setting will not be applied until the system is rebooted.
    
    The recommended state for this setting is: Enabled: Authenticated.
    
    Rationale: Unauthenticated RPC communication can create a security vulnerability.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Rpc") do
    it { should have_property "RestrictRemoteClients" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Rpc") do
    its("RestrictRemoteClients") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.6.1_L1_Ensure_Allow_Microsoft_accounts_to_be_optional_is_set_to_Enabled" do
  title "(L1) Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled'"
  desc  "
    This policy setting lets you control whether Microsoft accounts are optional for Windows Store apps that require an account to sign in. This policy only affects Windows Store apps that support it. If you enable this policy setting, Windows Store apps that typically require a Microsoft account to sign in will allow users to sign in with an enterprise account instead. If you disable or do not configure this policy setting, users will need to sign in with a Microsoft account.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Enabling this setting allows an organization to use their enterprise user accounts instead of using their Microsoft accounts when accessing Windows store apps. This provides the organization with greater control over relevant credentials. Microsoft accounts cannot be centrally managed and as such enterprise credential security policies cannot be applied to them, which could put any information accessed by using Microsoft accounts at risk.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
    it { should have_property "MSAOptional" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
    its("MSAOptional") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.8.1_L1_Ensure_Disallow_Autoplay_for_non-volume_devices_is_set_to_Enabled" do
  title "(L1) Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled'"
  desc  "
    This policy setting disallows AutoPlay for MTP devices like cameras or phones.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: An attacker could use this feature to launch a program to damage a client computer or data on the computer.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Explorer") do
    it { should have_property "NoAutoplayfornonVolume" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Explorer") do
    its("NoAutoplayfornonVolume") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.8.2_L1_Ensure_Set_the_default_behavior_for_AutoRun_is_set_to_Enabled_Do_not_execute_any_autorun_commands" do
  title "(L1) Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'"
  desc  "
    This policy setting sets the default behavior for Autorun commands. Autorun commands are generally stored in autorun.inf files. They often launch the installation program or other routines.
    
    The recommended state for this setting is: Enabled: Do not execute any autorun commands.
    
    Rationale: Prior to Windows Vista, when media containing an autorun command is inserted, the system will automatically execute the program without user intervention. This creates a major security concern as code may be executed without user's knowledge. The default behavior starting with Windows Vista is to prompt the user whether autorun command is to be run. The autorun command is represented as a handler in the Autoplay dialog.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer") do
    it { should have_property "NoAutorun" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer") do
    its("NoAutorun") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.8.3_L1_Ensure_Turn_off_Autoplay_is_set_to_Enabled_All_drives" do
  title "(L1) Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'"
  desc  "
    Autoplay starts to read from a drive as soon as you insert media in the drive, which causes the setup file for programs or audio media to start immediately. An attacker could use this feature to launch a program to damage the computer or data on the computer. You can enable the Turn off Autoplay setting to disable the Autoplay feature. Autoplay is disabled by default on some removable drive types, such as floppy disk and network drives, but not on CD-ROM drives.
    
    **Note:** You cannot use this policy setting to enable Autoplay on computer drives in which it is disabled by default, such as floppy disk and network drives.
    
    The recommended state for this setting is: Enabled: All drives.
    
    Rationale: An attacker could use this feature to launch a program to damage a client computer or data on the computer.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer") do
    it { should have_property "NoDriveTypeAutoRun" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer") do
    its("NoDriveTypeAutoRun") { should cmp == 255 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.10.1.1_L1_Ensure_Use_enhanced_anti-spoofing_when_available_is_set_to_Enabled" do
  title "(L1) Ensure 'Use enhanced anti-spoofing when available' is set to 'Enabled'"
  desc  "
    This policy setting determines whether enhanced anti-spoofing is configured for devices which support it.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Enterprise environments are now supporting a wider range of mobile devices, increasing the security on these devices will help protect against unauthorized access on your network.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Biometrics\\FacialFeatures") do
    it { should have_property "EnhancedAntiSpoofing" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Biometrics\\FacialFeatures") do
    its("EnhancedAntiSpoofing") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.12.1_L1_Ensure_Turn_off_Microsoft_consumer_experiences_is_set_to_Enabled" do
  title "(L1) Ensure 'Turn off Microsoft consumer experiences' is set to 'Enabled'"
  desc  "
    This policy setting turns off experiences that help consumers make the most of their devices and Microsoft account.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Having apps silently installed in an environment is not good security practice - especially if the apps send data back to a 3rd party.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent") do
    it { should have_property "DisableWindowsConsumerFeatures" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent") do
    its("DisableWindowsConsumerFeatures") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.13.1_L1_Ensure_Do_not_display_the_password_reveal_button_is_set_to_Enabled" do
  title "(L1) Ensure 'Do not display the password reveal button' is set to 'Enabled'"
  desc  "
    This policy setting allows you to configure the display of the password reveal button in password entry user experiences.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: This is a useful feature when entering a long and complex password, especially when using a touchscreen. The potential risk is that someone else may see your password while surreptitiously observing your screen.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\CredUI") do
    it { should have_property "DisablePasswordReveal" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\CredUI") do
    its("DisablePasswordReveal") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.13.2_L1_Ensure_Enumerate_administrator_accounts_on_elevation_is_set_to_Disabled" do
  title "(L1) Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled'"
  desc  "
    By default, all administrator accounts are displayed when you attempt to elevate a running application.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Users could see the list of administrator accounts, making it slightly easier for a malicious user who has logged onto a console session to try to crack the passwords of those accounts.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\CredUI") do
    it { should have_property "EnumerateAdministrators" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\CredUI") do
    its("EnumerateAdministrators") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.14.1_L1_Ensure_Allow_Telemetry_is_set_to_Enabled_0_-_Security_Enterprise_Only" do
  title "(L1) Ensure 'Allow Telemetry' is set to 'Enabled: 0 - Security [Enterprise Only]'"
  desc  "
    This policy setting determines the amount of diagnostic and usage data reported to Microsoft.
    
    A value of 0 will send minimal data to Microsoft. This data includes Malicious Software Removal Tool (MSRT)  Windows Defender data, if enabled, and telemetry client settings. Setting a value of 0 applies to enterprise, EDU, IoT and server devices only. Setting a value of 0 for other devices is equivalent to choosing a value of 1. A value of 1 sends only a basic amount of diagnostic and usage data. Note that setting values of 0 or 1 will degrade certain experiences on the device. A value of 2 sends enhanced diagnostic and usage data. A value of 3 sends the same data as a value of 2, plus additional diagnostics data, including the files and content that may have caused the problem. Windows 10 telemetry settings applies to the Windows operating system and some first party apps. This setting does not apply to third party apps running on Windows 10.
    
    If you disable or do not configure this policy setting, users can configure the Telemetry level in Settings.
    
    The recommended state for this setting is: Enabled: 0 - Security [Enterprise Only].
    
    Rationale: Sending any data to a 3rd party vendor is a security concern and should only be done on an as needed basis.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\DataCollection") do
    it { should have_property "AllowTelemetry" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\DataCollection") do
    its("AllowTelemetry") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.14.2_L1_Ensure_Disable_pre-release_features_or_settings_is_set_to_Disabled" do
  title "(L1) Ensure 'Disable pre-release features or settings' is set to 'Disabled'"
  desc  "
    This policy setting determines the level that Microsoft can experiment with the product to study user preferences or device behavior. A value of 1 permits Microsoft to configure device settings only. A value of 2 allows Microsoft to conduct full experimentations.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: It can be dangerous in an Enterprise environment if experimental features are allowed because this can introduce bugs and security holes into systems, making it easier for an attacker to gain access.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PreviewBuilds") do
    it { should have_property "EnableConfigFlighting" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PreviewBuilds") do
    its("EnableConfigFlighting") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.14.3_L1_Ensure_Do_not_show_feedback_notifications_is_set_to_Enabled" do
  title "(L1) Ensure 'Do not show feedback notifications' is set to 'Enabled'"
  desc  "
    This policy setting allows an organization to prevent its devices from showing feedback questions from Microsoft.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: In an enterprise environment users should not be sending any feedback to 3rd party vendors.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection") do
    it { should have_property "DoNotShowFeedbackNotifications" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection") do
    its("DoNotShowFeedbackNotifications") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.14.4_L1_Ensure_Toggle_user_control_over_Insider_builds_is_set_to_Disabled" do
  title "(L1) Ensure 'Toggle user control over Insider builds' is set to 'Disabled'"
  desc  "
    This policy setting determines whether users can access the Insider build controls in the Advanced Options for Windows Update. These controls are located under \"Get Insider builds,\" and enable users to make their devices available for downloading and installing Windows preview software.
    
    The recommended state for this setting is: Disabled.
    
    **Note:** This policy setting applies only to devices running Windows 10 Pro, Windows 10 Enterprise, or Server 2016.
    
    Rationale: It can be dangerous in an Enterprise environment if experimental features are allowed because this can introduce bugs and security holes into systems allowing an attacker to gain access.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PreviewBuilds") do
    it { should have_property "AllowBuildPreview" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PreviewBuilds") do
    its("AllowBuildPreview") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.15.1_L1_Ensure_Download_Mode_is_set_to_Enabled_None_or_LAN_or_Group_or_Disabled" do
  title "(L1) Ensure 'Download Mode' is set to 'Enabled: None or LAN or Group' or 'Disabled'"
  desc  "
    Set this policy to configure the use of Windows Update Delivery Optimization in downloads of Windows Apps and Updates. Available mode are: 0=disable 1=peers on same NAT only 2=Local Network / Private Peering (PCs in the same domain by default) 3= Internet Peering
    
    The recommended state for this setting is: Enabled: None or LAN or Group or Disabled.
    
    Rationale: Do to privacy concerns and security risks, updates should only be downloaded from a trusted machine on the internal network that received its updates from a trusted source and approved by the network administrator.
  "
  impact 1.0
  describe.one do
    describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\DeliveryOptimization") do
    it { should have_property "DODownloadMode" }
    its("DODownloadMode") { should cmp <= 2 }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\DeliveryOptimization") do
    it { should_not have_property "DODownloadMode" }
  end
 end
end

# control "xccdf_org.cisecurity.benchmarks_rule_18.9.22.1_L1_Ensure_EMET_5.5_or_higher_is_installed" do
#   title "(L1) Ensure 'EMET 5.5' or higher is installed"
#   desc  "
#     The Enhanced Mitigation Experience Toolkit (EMET) is free, supported, software developed by Microsoft that allows an enterprise to apply exploit mitigations to applications that run on Windows.
    
#     Rationale: EMET mitigations help reduce the reliability of exploits that target vulnerable software running on Windows
#   "
#   impact 1.0
#   describe registry_key("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services\\EMET_Service") do
#     it { should have_property "Start" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services\\EMET_Service") do
#     its("Start") { should cmp == 2 }
#   end
# end

# control "xccdf_org.cisecurity.benchmarks_rule_18.9.22.2_L1_Ensure_Default_Action_and_Mitigation_Settings_is_set_to_Enabled_plus_subsettings" do
#   title "(L1) Ensure 'Default Action and Mitigation Settings' is set to 'Enabled' (plus subsettings)"
#   desc  "
#     This setting configures the default action after detection and advanced ROP mitigation.
    
#     The recommended state for this setting is:
    
#     Default Action and Mitigation Settings - Enabled
#     Deep Hooks - Enabled
#     Anti Detours - Enabled
#     Banned Functions - Enabled
#     Exploit Action - User Configured
    
#     Rationale: These advanced mitigations for ROP mitigations apply to all configured software in EMET.
#     **Deep Hooks** protects critical APIs and the subsequent lower level APIs used by the top level critical API.
#     **Anti Detours** renders ineffective exploits that evade hooks by executing a copy of the hooked function prologue and then jump to the function past the prologue.
#     **Banned Functions** will block calls to **ntdll!LdrHotPatchRoutine** to mitigate potential exploits abusing the API.
#   "
#   impact 1.0
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\SysSettings") do
#     it { should have_property "AntiDetours" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\SysSettings") do
#     its("AntiDetours") { should cmp == 1 }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\SysSettings") do
#     it { should have_property "BannedFunctions" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\SysSettings") do
#     its("BannedFunctions") { should cmp == 1 }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\SysSettings") do
#     it { should have_property "DeepHooks" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\SysSettings") do
#     its("DeepHooks") { should cmp == 1 }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\SysSettings") do
#     it { should have_property "ExploitAction" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\SysSettings") do
#     its("ExploitAction") { should cmp == 2 }
#   end
# end

# control "xccdf_org.cisecurity.benchmarks_rule_18.9.22.3_L1_Ensure_Default_Protections_for_Internet_Explorer_is_set_to_Enabled" do
#   title "(L1) Ensure 'Default Protections for Internet Explorer' is set to 'Enabled'"
#   desc  "
#     This settings determine if EMET mitigations are applied to Internet Explorer.
    
#     The recommended state for this setting is: Enabled.
    
#     Rationale: Applying EMET mitigations to Internet Explorer will help reduce the reliability of exploits that target it.
#   "
#   impact 1.0
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "IE" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("IE") { should eq "*\\Internet Explorer\\iexplore.exe" }
#   end
# end

# control "xccdf_org.cisecurity.benchmarks_rule_18.9.22.4_L1_Ensure_Default_Protections_for_Popular_Software_is_set_to_Enabled" do
#   title "(L1) Ensure 'Default Protections for Popular Software' is set to 'Enabled'"
#   desc  "
#     This settings determine if EMET mitigations are applied to other popular software.
    
#     The recommended state for this setting is: Enabled.
    
#     Rationale: Applying EMET mitigations to popular software packages will help reduce the reliability of exploits that target them.
#   "
#   impact 1.0
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "7z" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("7z") { should match(//) }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "7zFM" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("7zFM") { should match(//) }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "7zGUI" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("7zGUI") { should match(//) }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "Chrome" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("Chrome") { should eq "*\\Google\\Chrome\\Application\\chrome.exe -SEHOP" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "Firefox" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("Firefox") { should eq "*\\Mozilla Firefox\\firefox.exe" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "FirefoxPluginContainer" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("FirefoxPluginContainer") { should eq "*\\Mozilla Firefox\\plugin-container.exe" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "FoxitReader" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("FoxitReader") { should eq "*\\Foxit Reader\\Foxit Reader.exe" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "GoogleTalk" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("GoogleTalk") { should eq "*\\Google\\Google Talk\\googletalk.exe -DEP -SEHOP" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "iTunes" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("iTunes") { should eq "*\\iTunes\\iTunes.exe" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "LiveWriter" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("LiveWriter") { should eq "*\\Windows Live\\Writer\\WindowsLiveWriter.exe" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "LyncCommunicator" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("LyncCommunicator") { should eq "*\\Microsoft Lync\\communicator.exe" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "mIRC" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("mIRC") { should eq "*\\mIRC\\mirc.exe" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "Opera" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("Opera") { should eq "*\\Opera\\opera.exe" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "PhotoGallery" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("PhotoGallery") { should eq "*\\Windows Live\\Photo Gallery\\WLXPhotoGallery.exe" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "Photoshop" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("Photoshop") { should eq "*\\Adobe\\Adobe Photoshop CS*\\Photoshop.exe" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "Pidgin" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("Pidgin") { should eq "*\\Pidgin\\pidgin.exe" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "QuickTimePlayer" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("QuickTimePlayer") { should match(//) }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "RealConverter" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("RealConverter") { should eq "*\\Real\\RealPlayer\\realconverter.exe" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "RealPlayer" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("RealPlayer") { should eq "*\\Real\\RealPlayer\\realplay.exe" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "Safari" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("Safari") { should eq "*\\Safari\\Safari.exe" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "SkyDrive" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("SkyDrive") { should eq "*\\SkyDrive\\SkyDrive.exe" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "Skype" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("Skype") { should eq "*\\Skype\\Phone\\Skype.exe -EAF" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "Thunderbird" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("Thunderbird") { should match(//) }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "ThunderbirdPluginContainer" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("ThunderbirdPluginContainer") { should eq "*\\Mozilla Thunderbird\\plugin-container.exe" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "UnRAR" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("UnRAR") { should eq "*\\WinRAR\\unrar.exe" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "VLC" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("VLC") { should eq "*\\VideoLAN\\VLC\\vlc.exe" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "Winamp" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("Winamp") { should eq "*\\Winamp\\winamp.exe" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "WindowsMediaPlayer" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("WindowsMediaPlayer") { should match(//) }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "WinRARConsole" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("WinRARConsole") { should eq "*\\WinRAR\\rar.exe" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "WinRARGUI" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("WinRARGUI") { should eq "*\\WinRAR\\winrar.exe" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "Winzip" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("Winzip") { should eq "*\\WinZip\\winzip32.exe" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "Winzip64" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("Winzip64") { should eq "*\\WinZip\\winzip64.exe" }
#   end
# end

# control "xccdf_org.cisecurity.benchmarks_rule_18.9.22.5_L1_Ensure_Default_Protections_for_Recommended_Software_is_set_to_Enabled" do
#   title "(L1) Ensure 'Default Protections for Recommended Software' is set to 'Enabled'"
#   desc  "
#     This settings determine if recommended EMET mitigations are applied to WordPad, applications that are part of the Microsoft Office suite, Adobe Acrobat, Adobe Reader, and Oracle Java.
    
#     The recommended state for this setting is: Enabled.
    
#     Rationale: Applying EMET mitigations to recommended software will help reduce the reliability of exploits that target them.
#   "
#   impact 1.0
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "Access" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("Access") { should eq "*\\OFFICE1*\\MSACCESS.EXE" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "Acrobat" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("Acrobat") { should eq "*\\Adobe\\Acrobat*\\Acrobat\\Acrobat.exe" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "AcrobatReader" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("AcrobatReader") { should eq "*\\Adobe\\Reader*\\Reader\\AcroRd32.exe" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "Excel" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("Excel") { should eq "*\\OFFICE1*\\EXCEL.EXE" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "InfoPath" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("InfoPath") { should eq "*\\OFFICE1*\\INFOPATH.EXE" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "jre6_java" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("jre6_java") { should eq "*\\Java\\jre6\\bin\\java.exe -HeapSpray" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "jre6_javaw" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("jre6_javaw") { should eq "*\\Java\\jre6\\bin\\javaw.exe -HeapSpray" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "jre6_javaws" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("jre6_javaws") { should eq "*\\Java\\jre6\\bin\\javaws.exe -HeapSpray" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "jre7_java" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("jre7_java") { should eq "*\\Java\\jre7\\bin\\java.exe -HeapSpray" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "jre7_javaw" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("jre7_javaw") { should eq "*\\Java\\jre7\\bin\\javaw.exe -HeapSpray" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "jre7_javaws" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("jre7_javaws") { should eq "*\\Java\\jre7\\bin\\javaws.exe -HeapSpray" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "Lync" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("Lync") { should eq "*\\OFFICE1*\\LYNC.EXE" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "Outlook" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("Outlook") { should eq "*\\OFFICE1*\\OUTLOOK.EXE" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "Picture Manager" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("Picture Manager") { should eq "*\\OFFICE1*\\OIS.EXE" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "PowerPoint" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("PowerPoint") { should eq "*\\OFFICE1*\\POWERPNT.EXE" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "PPTViewer" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("PPTViewer") { should eq "*\\OFFICE1*\\PPTVIEW.EXE" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "Publisher" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("Publisher") { should eq "*\\OFFICE1*\\MSPUB.EXE" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "Visio" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("Visio") { should eq "*\\OFFICE1*\\VISIO.EXE" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "VisioViewer" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("VisioViewer") { should eq "*\\OFFICE1*\\VPREVIEW.EXE" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "Word" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("Word") { should eq "*\\OFFICE1*\\WINWORD.EXE" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     it { should have_property "Wordpad" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
#     its("Wordpad") { should eq "*\\Windows NT\\Accessories\\wordpad.exe" }
#   end
# end

# control "xccdf_org.cisecurity.benchmarks_rule_18.9.22.6_L1_Ensure_System_ASLR_is_set_to_Enabled_Application_Opt-In" do
#   title "(L1) Ensure 'System ASLR' is set to 'Enabled: Application Opt-In'"
#   desc  "
#     This setting determines how applications become enrolled in address space layout randomization (ASLR).
    
#     The recommended state for this setting is: Enabled: Application Opt-In.
    
#     Rationale: ASLR reduces the predictability of process memory, which in-turn helps reduce the reliability of exploits targeting memory corruption vulnerabilities.
#   "
#   impact 1.0
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\SysSettings") do
#     it { should have_property "ASLR" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\SysSettings") do
#     its("ASLR") { should cmp == 3 }
#   end
# end

# control "xccdf_org.cisecurity.benchmarks_rule_18.9.22.7_L1_Ensure_System_DEP_is_set_to_Enabled_Application_Opt-Out" do
#   title "(L1) Ensure 'System DEP' is set to 'Enabled: Application Opt-Out'"
#   desc  "
#     This setting determines how applications become enrolled in data execution protection (DEP).
    
#     The recommended state for this setting is: Enabled: Application Opt-Out.
    
#     Rationale: DEP marks pages of application memory as non-executable, which reduces a given exploit's ability to run attacker-controlled code.
#   "
#   impact 1.0
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\SysSettings") do
#     it { should have_property "DEP" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\SysSettings") do
#     its("DEP") { should cmp == 2 }
#   end
# end

# control "xccdf_org.cisecurity.benchmarks_rule_18.9.22.8_L1_Ensure_System_SEHOP_is_set_to_Enabled_Application_Opt-Out" do
#   title "(L1) Ensure 'System SEHOP' is set to 'Enabled: Application Opt-Out'"
#   desc  "
#     This setting determines how applications become enrolled in structured exception handler overwrite protection (SEHOP).
    
#     The recommended state for this setting is: Enabled: Application Opt-Out.
    
#     Rationale: When a software component suffers from a memory corruption vulnerability, an exploit may be able to overwrite memory that contains data structures that control how the software handles exceptions. By corrupting these structures in a controlled manner, an exploit may be able to execute arbitrary code. SEHOP verifies the integrity of those structures before they are used to handle exceptions, which reduces the reliability of exploits that leverage structured exception handler overwrites.
#   "
#   impact 1.0
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\SysSettings") do
#     it { should have_property "SEHOP" }
#   end
#   describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\SysSettings") do
#     its("SEHOP") { should cmp == 2 }
#   end
# end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.24.1.1_L1_Ensure_Application_Control_Event_Log_behavior_when_the_log_file_reaches_its_maximum_size_is_set_to_Disabled" do
  title "(L1) Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
  desc  "
    This policy setting controls Event Log behavior when the log file reaches its maximum size. If you enable this policy setting and a log file reaches its maximum size, new events are not written to the log and are lost. If you disable or do not configure this policy setting and a log file reaches its maximum size, new events overwrite old events.
    
    The recommended state for this setting is: Disabled.
    
    **Note:** Old events may or may not be retained according to the \"Backup log automatically when full\"&#x9D; policy setting.
    
    Rationale: If new events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Application") do
    it { should have_property "Retention" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Application") do
    its("Retention") { should eq "0" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.24.1.2_L1_Ensure_Application_Specify_the_maximum_log_file_size_KB_is_set_to_Enabled_32768_or_greater" do
  title "(L1) Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'"
  desc  "
    This policy setting specifies the maximum size of the log file in kilobytes. If you enable this policy setting, you can configure the maximum log file size to be between 1 megabyte (1,024 kilobytes) and 2 terabytes (2,147,483,647 kilobytes) in kilobyte increments. If you disable or do not configure this policy setting, the maximum size of the log file will be set to the locally configured value. This value can be changed by the local administrator using the Log Properties dialog and it defaults to 20 megabytes.
    
    The recommended state for this setting is: Enabled: 32,768 or greater.
    
    Rationale: If events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Application") do
    it { should have_property "MaxSize" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Application") do
    its("MaxSize") { should cmp >= 32768 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.24.2.1_L1_Ensure_Security_Control_Event_Log_behavior_when_the_log_file_reaches_its_maximum_size_is_set_to_Disabled" do
  title "(L1) Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
  desc  "
    This policy setting controls Event Log behavior when the log file reaches its maximum size.
    
    If you enable this policy setting and a log file reaches its maximum size, new events are not written to the log and are lost.
    
    If you disable or do not configure this policy setting and a log file reaches its maximum size, new events overwrite old events.
    
    The recommended state for this setting is: Disabled.
    
    **Note:** Old events may or may not be retained according to the \"Backup log automatically when full\"&#x9D; policy setting.
    
    Rationale: If new events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Security") do
    it { should have_property "Retention" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Security") do
    its("Retention") { should eq "0" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.24.2.2_L1_Ensure_Security_Specify_the_maximum_log_file_size_KB_is_set_to_Enabled_196608_or_greater" do
  title "(L1) Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'"
  desc  "
    This policy setting specifies the maximum size of the log file in kilobytes. If you enable this policy setting, you can configure the maximum log file size to be between 1 megabyte (1,024 kilobytes) and 2 terabytes (2,147,483,647 kilobytes) in kilobyte increments. If you disable or do not configure this policy setting, the maximum size of the log file will be set to the locally configured value. This value can be changed by the local administrator using the Log Properties dialog and it defaults to 20 megabytes.
    
    The recommended state for this setting is: Enabled: 196,608 or greater.
    
    Rationale: If events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Security") do
    it { should have_property "MaxSize" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Security") do
    its("MaxSize") { should cmp >= 196608 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.24.3.1_L1_Ensure_Setup_Control_Event_Log_behavior_when_the_log_file_reaches_its_maximum_size_is_set_to_Disabled" do
  title "(L1) Ensure 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
  desc  "
    This policy setting controls Event Log behavior when the log file reaches its maximum size.
    
    If you enable this policy setting and a log file reaches its maximum size, new events are not written to the log and are lost.
    
    If you disable or do not configure this policy setting and a log file reaches its maximum size, new events overwrite old events.
    
    The recommended state for this setting is: Disabled.
    
    **Note:** Old events may or may not be retained according to the \"Backup log automatically when full\"&#x9D; policy setting.
    
    Rationale: If new events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Setup") do
    it { should have_property "Retention" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Setup") do
    its("Retention") { should eq "0" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.24.3.2_L1_Ensure_Setup_Specify_the_maximum_log_file_size_KB_is_set_to_Enabled_32768_or_greater" do
  title "(L1) Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'"
  desc  "
    This policy setting specifies the maximum size of the log file in kilobytes. If you enable this policy setting, you can configure the maximum log file size to be between 1 megabyte (1,024 kilobytes) and 2 terabytes (2,147,483,647 kilobytes) in kilobyte increments. If you disable or do not configure this policy setting, the maximum size of the log file will be set to the locally configured value. This value can be changed by the local administrator using the Log Properties dialog and it defaults to 20 megabytes.
    
    The recommended state for this setting is: Enabled: 32,768 or greater.
    
    Rationale: If events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Setup") do
    it { should have_property "MaxSize" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Setup") do
    its("MaxSize") { should cmp >= 32768 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.24.4.1_L1_Ensure_System_Control_Event_Log_behavior_when_the_log_file_reaches_its_maximum_size_is_set_to_Disabled" do
  title "(L1) Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
  desc  "
    This policy setting controls Event Log behavior when the log file reaches its maximum size.
    
    If you enable this policy setting and a log file reaches its maximum size, new events are not written to the log and are lost.
    
    If you disable or do not configure this policy setting and a log file reaches its maximum size, new events overwrite old events.
    
    The recommended state for this setting is: Disabled.
    
    **Note:** Old events may or may not be retained according to the \"Backup log automatically when full\"&#x9D; policy setting.
    
    Rationale: If new events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\System") do
    it { should have_property "Retention" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\System") do
    its("Retention") { should eq "0" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.24.4.2_L1_Ensure_System_Specify_the_maximum_log_file_size_KB_is_set_to_Enabled_32768_or_greater" do
  title "(L1) Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'"
  desc  "
    This policy setting specifies the maximum size of the log file in kilobytes. If you enable this policy setting, you can configure the maximum log file size to be between 1 megabyte (1,024 kilobytes) and 2 terabytes (2,147,483,647 kilobytes) in kilobyte increments. If you disable or do not configure this policy setting, the maximum size of the log file will be set to the locally configured value. This value can be changed by the local administrator using the Log Properties dialog and it defaults to 20 megabytes.
    
    The recommended state for this setting is: Enabled: 32,768 or greater.
    
    Rationale: If events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\System") do
    it { should have_property "MaxSize" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\System") do
    its("MaxSize") { should cmp >= 32768 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.28.2_L1_Ensure_Configure_Windows_SmartScreen_is_set_to_Enabled_Require_approval_from_an_administrator_before_running_downloaded_unknown_software" do
  title "(L1) Ensure 'Configure Windows SmartScreen' is set to 'Enabled: Require approval from an administrator before running downloaded unknown software'"
  desc  "
    This policy setting allows you to manage the behavior of Windows SmartScreen. Windows SmartScreen helps keep PCs safer by warning users before running unrecognized programs downloaded from the Internet. Some information is sent to Microsoft about files and programs run on PCs with this feature enabled.
    
    If you enable this policy setting, Windows SmartScreen behavior may be controlled by setting one of the following options:
    
    * Require approval from an administrator before running downloaded unknown software
    * Give user a warning before running downloaded unknown software
    * Turn off SmartScreen
    If you disable or do not configure this policy setting, Windows SmartScreen behavior is managed by administrators on the PC by using Windows SmartScreen Settings in Action Center.
    
    The recommended state for this setting is: Enabled: Require approval from an administrator before running downloaded unknown software.
    
    Rationale: Windows SmartScreen helps keep PCs safer by warning users before running unrecognized programs downloaded from the Internet. However, due to the fact that some information is sent to Microsoft about files and programs run on PCs some organizations may prefer to disable it.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System") do
    it { should have_property "EnableSmartScreen" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System") do
    its("EnableSmartScreen") { should cmp == 2 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.28.3_L1_Ensure_Turn_off_Data_Execution_Prevention_for_Explorer_is_set_to_Disabled" do
  title "(L1) Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled'"
  desc  "
    Disabling data execution prevention can allow certain legacy plug-in applications to function without terminating Explorer.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Data Execution Prevention is an important security feature supported by Explorer that helps to limit the impact of certain types of malware.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Explorer") do
    it { should have_property "NoDataExecutionPrevention" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Explorer") do
    its("NoDataExecutionPrevention") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.28.4_L1_Ensure_Turn_off_heap_termination_on_corruption_is_set_to_Disabled" do
  title "(L1) Ensure 'Turn off heap termination on corruption' is set to 'Disabled'"
  desc  "
    Legacy plug-in applications may continue to function when a File Explorer session has become corrupt. Disabling this feature will prevent this.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Allowing an application to function after its session has become corrupt increases the risk posture to the system.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Explorer") do
    it { should have_property "NoHeapTerminationOnCorruption" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Explorer") do
    its("NoHeapTerminationOnCorruption") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.28.5_L1_Ensure_Turn_off_shell_protocol_protected_mode_is_set_to_Disabled" do
  title "(L1) Ensure 'Turn off shell protocol protected mode' is set to 'Disabled'"
  desc  "
    This policy setting allows you to configure the amount of functionality that the shell protocol can have. When using the full functionality of this protocol applications can open folders and launch files. The protected mode reduces the functionality of this protocol allowing applications to only open a limited set of folders. Applications are not able to open files with this protocol when it is in the protected mode. It is recommended to leave this protocol in the protected mode to increase the security of Windows.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Limiting the opening of files and folders to a limited set reduces the attack surface of the system.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer") do
    it { should have_property "PreXPSP2ShellProtocolBehavior" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer") do
    its("PreXPSP2ShellProtocolBehavior") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.31.1_L1_Ensure_Prevent_the_computer_from_joining_a_homegroup_is_set_to_Enabled" do
  title "(L1) Ensure 'Prevent the computer from joining a homegroup' is set to 'Enabled'"
  desc  "
    By default, users can add their computer to a homegroup on a home network.
    
    If you enable this policy setting, a user on this computer will not be able to add this computer to a homegroup. This setting does not affect other network sharing features.
    
    If you disable or do not configure this policy setting, a user can add this computer to a homegroup. However, data on a domain-joined computer is not shared with the homegroup. Configure this setting in a manner that is consistent with security and operational requirements of your organization.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: By default, domain joined computers can be joined to a HomeGroup. While resources on a domain-joined computer cannot be shared to the HomeGroup, information from the domain-joined computer can be leaked to other computers in the HomeGroup.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\HomeGroup") do
    it { should have_property "DisableHomeGroup" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\HomeGroup") do
    its("DisableHomeGroup") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.38.1_L1_Ensure_Configure_Cookies_is_set_to_Enabled_Block_only_3rd-party_cookies._or_higher" do
  title "(L1) Ensure 'Configure Cookies' is set to 'Enabled: Block only 3rd-party cookies.' or higher"
  desc  "
    This setting lets you configure how your company deals with cookies.
    
    The recommended state for this setting is: Enabled: Block only 3rd-party cookies. Configuring this setting to Enabled: Block all cookies. also conforms with the benchmark.
    
    Rationale: Cookies can pose a serious privacy concern, many websites depend on them for operation. It is recommended when possible to block 3rd party cookies in order to reduce tracking.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\Main") do
    it { should have_property "Cookies" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\Main") do
    its("Cookies") { should cmp <= 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.38.4_L1_Ensure_Dont_allow_WebRTC_to_share_the_LocalHost_IP_address_is_set_to_Enabled" do
  title "(L1) Ensure 'Don't allow WebRTC to share the LocalHost IP address' is set to 'Enabled'"
  desc  "
    This setting lets you decide whether an employee's LocalHost IP address shows while making phone calls using the WebRTC protocol.
    
    The recommended state for this setting is: Enabled
    
    Rationale: WebRTC is a Real-Time Communications open source project supported by all major browsers. Allowing a system's local IP address to be shared may be considered a privacy concern.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\Main") do
    it { should have_property "HideLocalHostIP" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\Main") do
    its("HideLocalHostIP") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.38.5_L1_Ensure_Turn_off_address_bar_search_suggestions_is_set_to_Disabled" do
  title "(L1) Ensure 'Turn off address bar search suggestions' is set to 'Disabled'"
  desc  "
    This setting lets you decide whether search suggestions should appear in the Address bar of Microsoft Edge.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Having search suggestions sent out to be processed is considered a privacy concern.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\SearchScopes") do
    it { should have_property "ShowSearchSuggestionsGlobal" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\SearchScopes") do
    its("ShowSearchSuggestionsGlobal") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.38.7_L1_Ensure_Turn_off_Password_Manager_is_set_to_Disabled" do
  title "(L1) Ensure 'Turn off Password Manager' is set to 'Disabled'"
  desc  "
    This setting lets you decide whether employees can save their passwords locally, using Password Manager.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Using Password Manager can potentially makes it easier for an unauthorized user who gains access to the user#x2019;s desktop (including a coworker who sits down at a user#x2019;s desk soon after the user walks away and forgets to lock their workstation), to log in to sites as the user, without needing to know or enter the password
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\Main") do
    it { should have_property "FormSuggest Passwords" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\Main") do
    its("FormSuggest Passwords") { should cmp "no" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.38.9_L1_Ensure_Turn_off_the_SmartScreen_Filter_is_set_to_Enabled" do
  title "(L1) Ensure 'Turn off the SmartScreen Filter' is set to 'Enabled'"
  desc  "
    This setting lets you decide whether to turn on SmartScreen Filter. SmartScreen Filter provides warning messages to help protect your employees from potential phishing scams and malicious software.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: SmartScreen serves an important purpose as it helps to warn users of possible malicious sites and files. Allowing users to turn off this setting can make the browser become more vulnerable to compromise.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\PhishingFilter") do
    it { should have_property "EnabledV9" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\PhishingFilter") do
    its("EnabledV9") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.43.1_L1_Ensure_Prevent_the_usage_of_OneDrive_for_file_storage_is_set_to_Enabled" do
  title "(L1) Ensure 'Prevent the usage of OneDrive for file storage' is set to 'Enabled'"
  desc  "
    This policy setting lets you prevent apps and features from working with files on OneDrive.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Enabling this setting prevents users from accidentally uploading confidential or sensitive corporate information to OneDrive cloud service.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\OneDrive") do
    it { should have_property "DisableFileSyncNGSC" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\OneDrive") do
    its("DisableFileSyncNGSC") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.48.2.2_L1_Ensure_Do_not_allow_passwords_to_be_saved_is_set_to_Enabled" do
  title "(L1) Ensure 'Do not allow passwords to be saved' is set to 'Enabled'"
  desc  "
    This policy setting helps prevent Remote Desktop Services / Terminal Services clients from saving passwords on a computer. Note If this policy setting was previously configured as Disabled or Not configured, any previously saved passwords will be deleted the first time a Terminal Services client disconnects from any server.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: An attacker with physical access to the computer may be able to break the protection guarding saved passwords. An attacker who compromises a user's account and connects to their computer could use saved passwords to gain access to additional hosts.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services") do
    it { should have_property "DisablePasswordSaving" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services") do
    its("DisablePasswordSaving") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.48.3.3.2_L1_Ensure_Do_not_allow_drive_redirection_is_set_to_Enabled" do
  title "(L1) Ensure 'Do not allow drive redirection' is set to 'Enabled'"
  desc  "
    This policy setting prevents users from sharing the local drives on their client computers to Terminal Servers that they access. Mapped drives appear in the session folder tree in Windows Explorer in the following format:
    
    [
                                  \\\\TSClient\\
                                  
    <driveletter>
                                  $
                               ](file://\\\\TSClient\\<driveletter>$)
    
    If local drives are shared they are left vulnerable to intruders who want to exploit the data that is stored on them.
    
    The recommended state for this setting is: Enabled.</driveletter></driveletter>
    
    Rationale: Data could be forwarded from the user's Terminal Server session to the user's local computer without any direct user interaction.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services") do
    it { should have_property "fDisableCdm" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services") do
    its("fDisableCdm") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.48.3.9.1_L1_Ensure_Always_prompt_for_password_upon_connection_is_set_to_Enabled" do
  title "(L1) Ensure 'Always prompt for password upon connection' is set to 'Enabled'"
  desc  "
    This policy setting specifies whether Terminal Services always prompts the client computer for a password upon connection. You can use this policy setting to enforce a password prompt for users who log on to Terminal Services, even if they already provided the password in the Remote Desktop Connection client. By default, Terminal Services allows users to automatically log on if they enter a password in the Remote Desktop Connection client.
    
    **Note:** If you do not configure this policy setting, the local computer administrator can use the Terminal Services Configuration tool to either allow or prevent passwords from being automatically sent.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Users have the option to store both their username and password when they create a new Remote Desktop connection shortcut. If the server that runs Terminal Services allows users who have used this feature to log on to the server but not enter their password, then it is possible that an attacker who has gained physical access to the user's computer could connect to a Terminal Server through the Remote Desktop connection shortcut, even though they may not know the user's password.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services") do
    it { should have_property "fPromptForPassword" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services") do
    its("fPromptForPassword") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.48.3.9.2_L1_Ensure_Require_secure_RPC_communication_is_set_to_Enabled" do
  title "(L1) Ensure 'Require secure RPC communication' is set to 'Enabled'"
  desc  "
    This policy setting allows you to specify whether a terminal server requires secure remote procedure call (RPC) communication with all clients or allows unsecured communication.
    
    You can use this policy setting to strengthen the security of RPC communication with clients by allowing only authenticated and encrypted requests.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Allowing unsecure RPC communication can exposes the server to man in the middle attacks and data disclosure attacks.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services") do
    it { should have_property "fEncryptRPCTraffic" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services") do
    its("fEncryptRPCTraffic") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.48.3.9.3_L1_Ensure_Set_client_connection_encryption_level_is_set_to_Enabled_High_Level" do
  title "(L1) Ensure 'Set client connection encryption level' is set to 'Enabled: High Level'"
  desc  "
    This policy setting specifies whether the computer that is about to host the remote connection will enforce an encryption level for all data sent between it and the client computer for the remote session.
    
    The recommended state for this setting is: Enabled: High Level.
    
    Rationale: If Terminal Server client connections are allowed that use low level encryption, it is more likely that an attacker will be able to decrypt any captured Terminal Services network traffic.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services") do
    it { should have_property "MinEncryptionLevel" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services") do
    its("MinEncryptionLevel") { should cmp == 3 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.48.3.11.2_L1_Ensure_Do_not_use_temporary_folders_per_session_is_set_to_Disabled" do
  title "(L1) Ensure 'Do not use temporary folders per session' is set to 'Disabled'"
  desc  "
    By default, Remote Desktop Services creates a separate temporary folder on the RD Session Host server for each active session that a user maintains on the RD Session Host server. The temporary folder is created on the RD Session Host server in a Temp folder under the user's profile folder and is named with the \"sessionid.\" This temporary folder is used to store individual temporary files.
    
    To reclaim disk space, the temporary folder is deleted when the user logs off from a session.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: By Disabling this setting you are keeping the cached data independent for each session, both reducing the chance of problems from shared cached data between sessions, and keeping possibly sensitive data separate to each user session.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services") do
    it { should have_property "PerSessionTempDir" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services") do
    its("PerSessionTempDir") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.48.3.11.1_L1_Ensure_Do_not_delete_temp_folders_upon_exit_is_set_to_Disabled" do
  title "(L1) Ensure 'Do not delete temp folders upon exit' is set to 'Disabled'"
  desc  "
    This policy setting specifies whether Remote Desktop Services retains a user's per-session temporary folders at logoff.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Sensitive information could be contained inside the temporary folders and shared with other administrators that log into the system.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services") do
    it { should have_property "DeleteTempDirsOnExit" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services") do
    its("DeleteTempDirsOnExit") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.49.1_L1_Ensure_Prevent_downloading_of_enclosures_is_set_to_Enabled" do
  title "(L1) Ensure 'Prevent downloading of enclosures' is set to 'Enabled'"
  desc  "
    This policy setting prevents the user from having enclosures (file attachments) downloaded from a feed to the user's computer.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Allowing attachments to be downloaded through the RSS feed can introduce files that could have malicious intent.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Feeds") do
    it { should have_property "DisableEnclosureDownload" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Feeds") do
    its("DisableEnclosureDownload") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.50.2_L1_Ensure_Allow_Cortana_is_set_to_Disabled" do
  title "(L1) Ensure 'Allow Cortana' is set to 'Disabled'"
  desc  "
    This policy setting specifies whether Cortana is allowed on the device.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: If Cortana is enabled, sensitive information could be contained in search history and sent out to Microsoft.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search") do
    it { should have_property "AllowCortana" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search") do
    its("AllowCortana") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.50.3_L1_Ensure_Allow_indexing_of_encrypted_files_is_set_to_Disabled" do
  title "(L1) Ensure 'Allow indexing of encrypted files' is set to 'Disabled'"
  desc  "
    This policy setting allows encrypted items to be indexed. If you enable this policy setting, indexing will attempt to decrypt and index the content (access restrictions will still apply). If you disable this policy setting, the search service components (including non-Microsoft components) are expected not to index encrypted items or encrypted stores. This policy setting is not configured by default. If you do not configure this policy setting, the local setting, configured through Control Panel, will be used. By default, the Control Panel setting is set to not index encrypted content. When this setting is enabled or disabled, the index is rebuilt completely. Full volume encryption (such as BitLocker Drive Encryption or a non-Microsoft solution) must be used for the location of the index to maintain security for encrypted files.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Indexing and allowing users to search encrypted files could potentially reveal confidential data stored within the encrypted files.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search") do
    it { should have_property "AllowIndexingEncryptedStoresOrItems" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search") do
    its("AllowIndexingEncryptedStoresOrItems") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.50.4_L1_Ensure_Allow_search_and_Cortana_to_use_location_is_set_to_Disabled" do
  title "(L1) Ensure 'Allow search and Cortana to use location' is set to 'Disabled'"
  desc  "
    This policy setting specifies whether search and Cortana can provide location aware search and Cortana results.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: In an Enterprise having Cortana and Search having access to location is unnecessary. Organizations may not want this information shared out.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search") do
    it { should have_property "AllowSearchToUseLocation" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search") do
    its("AllowSearchToUseLocation") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.58.2_L1_Ensure_Turn_off_Automatic_Download_and_Install_of_updates_is_set_to_Disabled" do
  title "(L1) Ensure 'Turn off Automatic Download and Install of updates' is set to 'Disabled'"
  desc  "
    This setting enables or disables the automatic download and installation of app updates.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Keeping your system properly patched can help protect against 0 day vulnerabilities.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsStore") do
    it { should have_property "AutoDownload" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsStore") do
    its("AutoDownload") { should cmp == 4 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.58.3_L1_Ensure_Turn_off_the_offer_to_update_to_the_latest_version_of_Windows_is_set_to_Enabled" do
  title "(L1) Ensure 'Turn off the offer to update to the latest version of Windows' is set to 'Enabled'"
  desc  "
    Enables or disables the Store offer to update to the latest version of Windows.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Unplanned OS upgrades can lead to more preventable support calls. IT should be pushing only approved updates to the machine.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsStore") do
    it { should have_property "DisableOSUpgrade" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsStore") do
    its("DisableOSUpgrade") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.68.1_L1_Ensure_Enables_or_disables_Windows_Game_Recording_and_Broadcasting_is_set_to_Disabled" do
  title "(L1) Ensure 'Enables or disables Windows Game Recording and Broadcasting' is set to 'Disabled'"
  desc  "
    This setting enables or disables the Windows Game Recording and Broadcasting features. If you disable this setting, Windows Game Recording will not be allowed. If the setting is enabled or not configured, then Recording and Broadcasting (streaming) will be allowed.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: If this setting is allowed users could record and broadcast session info to external sites which is a privacy concern.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR") do
    it { should have_property "AllowGameDVR" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR") do
    its("AllowGameDVR") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.69.1_L1_Ensure_Allow_user_control_over_installs_is_set_to_Disabled" do
  title "(L1) Ensure 'Allow user control over installs' is set to 'Disabled'"
  desc  "
    Permits users to change installation options that typically are available only to system administrators. The security features of Windows Installer prevent users from changing installation options typically reserved for system administrators, such as specifying the directory to which files are installed. If Windows Installer detects that an installation package has permitted the user to change a protected option, it stops the installation and displays a message. These security features operate only when the installation program is running in a privileged security context in which it has access to directories denied to the user.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: In an Enterprise environment, only IT staff with administrative rights should be installing or changing software on a system. Allowing users the ability can risk unapproved software from being installed our removed from a system which could cause the system to become vulnerable.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer") do
    it { should have_property "EnableUserControl" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer") do
    its("EnableUserControl") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.69.2_L1_Ensure_Always_install_with_elevated_privileges_is_set_to_Disabled" do
  title "(L1) Ensure 'Always install with elevated privileges' is set to 'Disabled'"
  desc  "
    Directs Windows Installer to use system permissions when it installs any program on the system.
    
    This setting extends elevated privileges to all programs. These privileges are usually reserved for programs that have been assigned to the user (offered on the desktop), assigned to the computer (installed automatically), or made available in Add or Remove Programs in Control Panel. This setting lets users install programs that require access to directories that the user might not have permission to view or change, including directories on highly restricted computers.
    
    If you disable this setting or do not configure it, the system applies the current user's permissions when it installs programs that a system administrator does not distribute or offer.
    
    **Note:** This setting appears both in the Computer Configuration and User Configuration folders. To make this setting effective, you must enable the setting in both folders.
    
    **Caution:** Skilled users can take advantage of the permissions this setting grants to change their privileges and gain permanent access to restricted files and folders. Note that the User Configuration version of this setting is not guaranteed to be secure.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Users with limited privileges can exploit this feature by creating a Windows Installer installation package that creates a new local account that belongs to the local built-in Administrators group, adds their current account to the local built-in Administrators group, installs malicious software, or performs other unauthorized activities.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer") do
    it { should have_property "AlwaysInstallElevated" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer") do
    its("AlwaysInstallElevated") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.70.1_L1_Ensure_Sign-in_last_interactive_user_automatically_after_a_system-initiated_restart_is_set_to_Disabled" do
  title "(L1) Ensure 'Sign-in last interactive user automatically after a system-initiated restart' is set to 'Disabled'"
  desc  "
    This policy setting controls whether a device will automatically sign-in the last interactive user after Windows Update restarts the system. If you enable or do not configure this policy setting the device securely saves the user's credentials (including the user name domain and encrypted password) to configure automatic sign-in after a Windows Update restart. After the Windows Update restart the user is automatically signed-in and the session is automatically locked with all the lock screen apps configured for that user. If you disable this policy setting the device does not store the user's credentials for automatic sign-in after a Windows Update restart. The users' lock screen apps are not restarted after the system restarts.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Disabling this feature will prevent the caching of user's credentials and unauthorized use of the device, and also ensure the user is aware of the restart.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
    it { should have_property "DisableAutomaticRestartSignOn" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
    its("DisableAutomaticRestartSignOn") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.79.1_L1_Ensure_Turn_on_PowerShell_Script_Block_Logging_is_set_to_Disabled" do
  title "(L1) Ensure 'Turn on PowerShell Script Block Logging' is set to 'Disabled'"
  desc  "
    This policy setting enables logging of all PowerShell script input to the Microsoft-Windows-PowerShell/Operational event log.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Due to the potential risks of capturing passwords in the logs. This setting should only be needed for debugging purposes, and not in normal operation, it is important to ensure this is set to Disabled.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging") do
    it { should have_property "EnableScriptBlockLogging" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging") do
    its("EnableScriptBlockLogging") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.79.2_L1_Ensure_Turn_on_PowerShell_Transcription_is_set_to_Disabled" do
  title "(L1) Ensure 'Turn on PowerShell Transcription' is set to 'Disabled'"
  desc  "
    This Policy setting lets you capture the input and output of Windows PowerShell commands into text-based transcripts.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: If this setting is enabled there is a risk that passwords could get stored in plain text in the PowerShell_transcript output file.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription") do
    it { should have_property "EnableTranscripting" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription") do
    its("EnableTranscripting") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.81.1.1_L1_Ensure_Allow_Basic_authentication_is_set_to_Disabled" do
  title "(L1) Ensure 'Allow Basic authentication' is set to 'Disabled'"
  desc  "
    This policy setting allows you to manage whether the Windows Remote Management (WinRM) client uses Basic authentication.
    
    If you enable this policy setting, the WinRM client will use Basic authentication. If WinRM is configured to use HTTP transport, then the user name and password are sent over the network as clear text.
    
    If you disable or do not configure this policy setting, then the WinRM client will not use Basic authentication.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Basic authentication is less robust than other authentication methods available in WinRM because credentials including passwords are transmitted in plain text. An attacker who is able to capture packets on the network where WinRM is running may be able to determine the credentials used for accessing remote hosts via WinRM.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client") do
    it { should have_property "AllowBasic" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client") do
    its("AllowBasic") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.81.1.2_L1_Ensure_Allow_unencrypted_traffic_is_set_to_Disabled" do
  title "(L1) Ensure 'Allow unencrypted traffic' is set to 'Disabled'"
  desc  "
    This policy setting allows you to manage whether the Windows Remote Management (WinRM) client sends and receives unencrypted messages over the network.
    
    If you enable this policy setting, the WinRM client sends and receives unencrypted messages over the network.
    
    If you disable or do not configure this policy setting, the WinRM client sends or receives only encrypted messages over the network.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Encrypting WinRM network traffic reduces the risk of an attacker viewing or modifying WinRM messages as they transit the network.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client") do
    it { should have_property "AllowUnencryptedTraffic" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client") do
    its("AllowUnencryptedTraffic") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.81.1.3_L1_Ensure_Disallow_Digest_authentication_is_set_to_Enabled" do
  title "(L1) Ensure 'Disallow Digest authentication' is set to 'Enabled'"
  desc  "
    This policy setting allows you to manage whether the Windows Remote Management (WinRM) client will not use Digest authentication.
    
    If you enable this policy setting, the WinRM client will not use Digest authentication.
    
    If you disable or do not configure this policy setting, the WinRM client will use Digest authentication.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Digest authentication is less robust than other authentication methods available in WinRM, an attacker who is able to capture packets on the network where WinRM is running may be able to determine the credentials used for accessing remote hosts via WinRM.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client") do
    it { should have_property "AllowDigest" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client") do
    its("AllowDigest") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.81.2.1_L1_Ensure_Allow_Basic_authentication_is_set_to_Disabled" do
  title "(L1) Ensure 'Allow Basic authentication' is set to 'Disabled'"
  desc  "
    This policy setting allows you to manage whether the Windows Remote Management (WinRM) service accepts Basic authentication from a remote client.
    
    If you enable this policy setting, the WinRM service will accept Basic authentication from a remote client.
    
    If you disable or do not configure this policy setting, the WinRM service will not accept Basic authentication from a remote client.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Basic authentication is less robust than other authentication methods available in WinRM because credentials including passwords are transmitted in plain text. An attacker who is able to capture packets on the network where WinRM is running may be able to determine the credentials used for accessing remote hosts via WinRM.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service") do
    it { should have_property "AllowBasic" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service") do
    its("AllowBasic") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.81.2.2_L1_Ensure_Allow_unencrypted_traffic_is_set_to_Disabled" do
  title "(L1) Ensure 'Allow unencrypted traffic' is set to 'Disabled'"
  desc  "
    This policy setting allows you to manage whether the Windows Remote Management (WinRM) service sends and receives unencrypted messages over the network.
    
    If you enable this policy setting, the WinRM client sends and receives unencrypted messages over the network.
    
    If you disable or do not configure this policy setting, the WinRM client sends or receives only encrypted messages over the network.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Encrypting WinRM network traffic reduces the risk of an attacker viewing or modifying WinRM messages as they transit the network.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service") do
    it { should have_property "AllowUnencryptedTraffic" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service") do
    its("AllowUnencryptedTraffic") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.81.2.3_L1_Ensure_Disallow_WinRM_from_storing_RunAs_credentials_is_set_to_Enabled" do
  title "(L1) Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled'"
  desc  "
    This policy setting allows you to manage whether the Windows Remote Management (WinRM) service will not allow RunAs credentials to be stored for any plug-ins.
    
    If you enable this policy setting, the WinRM service will not allow the RunAsUser or RunAsPassword configuration values to be set for any plug-ins. If a plug-in has already set the RunAsUser and RunAsPassword configuration values, the RunAsPassword configuration value will be erased from the credential store on this computer.
    
    If you disable or do not configure this policy setting, the WinRM service will allow the RunAsUser and RunAsPassword configuration values to be set for plug-ins and the RunAsPassword value will be stored securely.
    
    If you enable and then disable this policy setting, any values that were previously configured for RunAsPassword will need to be reset.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Although the ability to store RunAs credentials is a convenient feature it increases the risk of account compromise slightly. For example, if you forget to lock your desktop before leaving it unattended for a few minutes another person could access not only the desktop of your computer but also any hosts you manage via WinRM with cached RunAs credentials.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service") do
    it { should have_property "DisableRunAs" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service") do
    its("DisableRunAs") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.85.1_L1_Ensure_Configure_Automatic_Updates_is_set_to_Enabled" do
  title "(L1) Ensure 'Configure Automatic Updates' is set to 'Enabled'"
  desc  "
    This policy setting specifies whether computers in your environment will receive security updates from Windows Update or WSUS. If you configure this policy setting to Enabled, the operating system will recognize when a network connection is available and then use the network connection to search Windows Update or your designated intranet site for updates that apply to them.
    
    After you configure this policy setting to Enabled, select one of the following three options in the Configure Automatic Updates Properties dialog box to specify how the service will work:
    - Notify before downloading any updates and notify again before installing them.
    - Download the updates automatically and notify when they are ready to be installed. (Default setting)
    - Automatically download updates and install them on the schedule specified below.
    
    If you disable this policy setting, you will need to download and manually install any available updates from Windows Update.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Although each version of Windows is thoroughly tested before release, it is possible that problems will be discovered after the products are shipped. The Configure Automatic Updates setting can help you ensure that the computers in your environment will always have the most recent critical operating system updates and service packs installed.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU") do
    it { should have_property "NoAutoUpdate" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU") do
    its("NoAutoUpdate") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.85.2_L1_Ensure_Configure_Automatic_Updates_Scheduled_install_day_is_set_to_0_-_Every_day" do
  title "(L1) Ensure 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day'"
  desc  "
    This policy setting specifies whether computers in your environment will receive security updates from Windows Update or WSUS. If you configure this policy setting to Enabled, the operating system will recognize when a network connection is available and then use the network connection to search Windows Update or your designated intranet site for updates that apply to them.
    
    After you configure this policy setting to Enabled, select one of the following three options in the Configure Automatic Updates Properties dialog box to specify how the service will work:
    - Notify before downloading any updates and notify again before installing them.
    - Download the updates automatically and notify when they are ready to be installed. (Default setting)
    - Automatically download updates and install them on the schedule specified below.
    
    If you disable this policy setting, you will need to download and manually install any available updates from Windows Update.
    
    The recommended state for this setting is: 0 - Every day.
    
    Rationale: Although each version of Windows is thoroughly tested before release, it is possible that problems will be discovered after the products are shipped. The Configure Automatic Updates setting can help you ensure that the computers in your environment will always have the most recent critical operating system updates and service packs installed.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU") do
    it { should have_property "ScheduledInstallDay" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU") do
    its("ScheduledInstallDay") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.85.3_L1_Ensure_Defer_Upgrades_and_Updates_is_set_to_Enabled_8_months_0_weeks" do
  title "(L1) Ensure 'Defer Upgrades and Updates' is set to 'Enabled: 8 months, 0 weeks'"
  desc  "
    If you enable this policy setting, in Pro and Enterprise SKUs you can defer upgrades till the next upgrade period (at least a few months). If you do not have it set you will receive upgrades once they are available that will be installed as part of your update policies. Security updates will not be impacted by this policy. For more information on available upgrades see [windows.com/itpro](http://windows.com/itpro).
    
    The recommended state for this setting is:
    
    Defer Upgrades and Updates - **Enabled**
    Defer upgrades for the following duration (months) - **8 months**
    Defer updates for the following duration (weeks) - **0 weeks**
    Pause Upgrades and Updates - **unchecked**
    
    Rationale: Forcing upgrades to features without testing in your environment could cause software incompatibilities as well as introducing new bugs into the operating system.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate") do
    it { should have_property "DeferUpgrade" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate") do
    its("DeferUpgrade") { should cmp == 1 }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate") do
    it { should have_property "DeferUpgradePeriod" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate") do
    its("DeferUpgradePeriod") { should cmp == 8 }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate") do
    it { should have_property "DeferUpdatePeriod" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate") do
    its("DeferUpdatePeriod") { should cmp == 0 }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate") do
    it { should_not have_property "PauseDeferrals" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.85.4_L1_Ensure_No_auto-restart_with_logged_on_users_for_scheduled_automatic_updates_installations_is_set_to_Disabled" do
  title "(L1) Ensure 'No auto-restart with logged on users for scheduled automatic updates installations' is set to 'Disabled'"
  desc  "
    This policy setting specifies that Automatic Updates will wait for computers to be restarted by the users who are logged on to them to complete a scheduled installation.
    
    If you enable the No auto-restart for scheduled Automatic Updates installations setting, Automatic Updates does not restart computers automatically during scheduled installations. Instead, Automatic Updates notifies users to restart their computers to complete the installations. You should note that Automatic Updates will not be able to detect future updates until restarts occur on the affected computers. If you disable or do not configure this setting, Automatic Updates will notify users that their computers will automatically restart in 5 minutes to complete the installations.
    
    The possible values for the No auto-restart for scheduled Automatic Updates installations setting are:
    - Enabled
    - Disabled
    - Not Configured
    
    **Note:** This setting applies only when you configure Automatic Updates to perform scheduled update installations. If you configure the Configure Automatic Updates setting to Disabled, this setting has no effect.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Sometimes updates require updated computers to be restarted to complete an installation. If the computer cannot restart automatically, then the most recent update will not completely install and no new updates will download to the computer until it is restarted.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU") do
    it { should have_property "NoAutoRebootWithLoggedOnUsers" }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU") do
    its("NoAutoRebootWithLoggedOnUsers") { should cmp == 0 }
  end
end
