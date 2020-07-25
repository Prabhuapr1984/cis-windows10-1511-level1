# encoding: UTF-8

control "xccdf_org.cisecurity.benchmarks_rule_19.1.3.1_L1_Ensure_Enable_screen_saver_is_set_to_Enabled" do
  title "(L1) Ensure 'Enable screen saver' is set to 'Enabled'"
  desc  "
    This policy setting allows you to manage whether or not screen savers run. If the Screen Saver setting is disabled screen savers do not run and the screen saver section of the Screen Saver tab in Display in Control Panel is disabled. If this setting is enabled a screen saver will run if the following two conditions are met: first, that a valid screen saver is specified on the client via the Screen Saver Executable Name group policy setting or Control Panel on the client. Second, the screensaver timeout is set to a value greater than zero via the Screen Saver Timeout group policy setting or Control Panel on the client.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: If a user forgets to lock their computer when they walk away it's possible that a passerby will hijack it.
  "
  impact 1.0
  registry_key({hive: 'HKEY_USERS'}).children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}\\[Ss][Oo][Ff][Tt][Ww][Aa][Rr][Ee]\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop/).each do |entry|
    describe registry_key(entry) do
      its("ScreenSaveActive") { should eq "1" }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_19.1.3.2_L1_Ensure_Force_specific_screen_saver_Screen_saver_executable_name_is_set_to_Enabled_scrnsave.scr" do
  title "(L1) Ensure 'Force specific screen saver: Screen saver executable name' is set to 'Enabled: scrnsave.scr'"
  desc  "
    This policy setting allows you to manage whether or not screen savers run. If the Screen Saver setting is disabled screen savers do not run and the screen saver section of the Screen Saver tab in Display in Control Panel is disabled. If this setting is enabled a screen saver will run if the following two conditions are met: first, that a valid screen saver is specified on the client via the Screen Saver Executable Name group policy setting or Control Panel on the client. Second, the screensaver timeout is set to a value greater than zero via the Screen Saver Timeout group policy setting or Control Panel on the client.
    
    The recommended state for this setting is: Enabled: scrnsave.scr.
    
    Rationale: If a user forgets to lock their computer when they walk away it's possible that a passerby will hijack it.
  "
  impact 1.0
  registry_key({hive: 'HKEY_USERS'}).children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}\\[Ss][Oo][Ff][Tt][Ww][Aa][Rr][Ee]\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop/).each do |entry|
    describe registry_key(entry) do
      its("SCRNSAVE.EXE") { should eq "scrnsave.scr" }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_19.1.3.3_L1_Ensure_Password_protect_the_screen_saver_is_set_to_Enabled" do
  title "(L1) Ensure 'Password protect the screen saver' is set to 'Enabled'"
  desc  "
    If the Password protect the screen saver setting is enabled, then all screen savers are password protected, if it is disabled then password protection cannot be set on any screen saver.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: If a user forgets to lock their computer when they walk away it is possible that a passerby will hijack it.
  "
  impact 1.0
  registry_key({hive: 'HKEY_USERS'}).children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}\\[Ss][Oo][Ff][Tt][Ww][Aa][Rr][Ee]\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop/).each do |entry|
    describe registry_key(entry) do
      its("ScreenSaverIsSecure") { should eq "1" }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_19.1.3.4_L1_Ensure_Screen_saver_timeout_is_set_to_Enabled_900_seconds_or_fewer_but_not_0" do
  title "(L1) Ensure 'Screen saver timeout' is set to 'Enabled: 900 seconds or fewer, but not 0'"
  desc  "
    If the Screen Saver Timeout setting is enabled, then the screen saver will be launched when the specified amount of time has passed since the last user action. Valid values range from 1 to 89,400 seconds (24 hours). The setting has no effect if the wait time is set to zero or no screen saver has been specified.
    
    The recommended state for this setting is: Enabled: 900 seconds or fewer, but not 0.
    
    Rationale: If a user forgets to lock their computer when they walk away it is possible that a passerby will hijack it.
  "
  impact 1.0
  registry_key({hive: 'HKEY_USERS'}).children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}\\[Ss][Oo][Ff][Tt][Ww][Aa][Rr][Ee]\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop/).each do |entry|
    describe registry_key(entry) do
      its("ScreenSaveTimeOut") { should cmp <= 900 }
    end
  end
  registry_key({hive: 'HKEY_USERS'}).children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}\\[Ss][Oo][Ff][Tt][Ww][Aa][Rr][Ee]\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop/).each do |entry|
    describe registry_key(entry) do
      its("ScreenSaveTimeOut") { should cmp =! 0 }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_19.5.1.1_L1_Ensure_Turn_off_toast_notifications_on_the_lock_screen_is_set_to_Enabled" do
  title "(L1) Ensure 'Turn off toast notifications on the lock screen' is set to 'Enabled'"
  desc  "
    This policy setting turns off toast notifications on the lock screen. If you enable this policy setting, applications will not be able to raise toast notifications on the lock screen. If you disable or do not configure this policy setting, toast notifications on the lock screen are enabled and can be turned off by the administrator or user. No reboots or service restarts are required for this policy setting to take effect.
    
    The recommended state for this setting is Enabled.
    
    Rationale: While this feature can be handy for users applications that provide toast notifications might display sensitive personal or business data while the device is unattended.
  "
  impact 1.0
  registry_key({hive: 'HKEY_USERS'}).children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}\\[Ss][Oo][Ff][Tt][Ww][Aa][Rr][Ee]\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications/).each do |entry|
    describe registry_key(entry) do
      its("NoToastApplicationNotificationOnLockScreen") { should cmp == 1 }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_19.7.4.1_L1_Ensure_Do_not_preserve_zone_information_in_file_attachments_is_set_to_Disabled" do
  title "(L1) Ensure 'Do not preserve zone information in file attachments' is set to 'Disabled'"
  desc  "
    This policy setting allows you to manage whether Windows marks file attachments from Internet Explorer or Microsoft Outlook' Express with information about their zone of origin (such as restricted, Internet, intranet, or local). This policy setting requires that files be downloaded to NTFS disk partitions to function correctly. If zone information is not preserved, Windows cannot make proper risk assessments based on the zone where the attachment came from.
    
    If the Do not preserve zone information in file attachments setting is enabled, file attachments are not marked with their zone information. If this policy setting is disabled, Windows is forced to store file attachments with their zone information.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: A file that is downloaded from a computer in the Internet or Restricted Sites zone may be moved to a location that makes it appear safe, like an intranet file share, and executed by an unsuspecting user.
  "
  impact 1.0
  registry_key({hive: 'HKEY_USERS'}).children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}\\[Ss][Oo][Ff][Tt][Ww][Aa][Rr][Ee]\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments/).each do |entry|
    describe registry_key(entry) do
      its("SaveZoneInformation") { should cmp == 2 }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_19.7.4.2_L1_Ensure_Notify_antivirus_programs_when_opening_attachments_is_set_to_Enabled" do
  title "(L1) Ensure 'Notify antivirus programs when opening attachments' is set to 'Enabled'"
  desc  "
    Antivirus programs are mandatory in many environments and provide a strong defense against attack.
    
    The Notify antivirus programs when opening attachments setting allows you to manage how registered antivirus programs are notified. When enabled, this policy setting configures Windows to call the registered antivirus program and have it scan file attachments when they are opened by users. If the antivirus scan fails, the attachments are blocked from being opened. If this policy setting is disabled, Windows does not call the registered antivirus program when file attachments are opened.
    
    The recommended state for this setting is: Enabled.
    
    **Note:** An updated antivirus program must be installed for this policy setting to function properly.
    
    Rationale: Antivirus programs that do not perform on-access checks may not be able to scan downloaded files.
  "
  impact 1.0
  registry_key({hive: 'HKEY_USERS'}).children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}\\[Ss][Oo][Ff][Tt][Ww][Aa][Rr][Ee]\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments/).each do |entry|
    describe registry_key(entry) do
      its("ScanWithAntiVirus") { should cmp == 3 }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_19.7.25.1_L1_Ensure_Prevent_users_from_sharing_files_within_their_profile._is_set_to_Enabled" do
  title "(L1) Ensure 'Prevent users from sharing files within their profile.' is set to 'Enabled'"
  desc  "
    This policy setting specifies whether users can share files within their profile. By default users are allowed to share files within their profile to other users on their network after an administrator opts in the computer. An administrator can opt in the computer by using the sharing wizard to share a file within their profile.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: If not properly controlled a user could accidentally share sensitive data with unauthorized users. In a corporate environment, the company should provide a managed location for file sharing, such as a file server or SharePoint.
  "
  impact 1.0
  registry_key({hive: 'HKEY_USERS'}).children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}\\[Ss][Oo][Ff][Tt][Ww][Aa][Rr][Ee]\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer/).each do |entry|
    describe registry_key(entry) do
      its("NoInplaceSharing") { should cmp == 1 }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_19.7.37.1_L1_Ensure_Always_install_with_elevated_privileges_is_set_to_Disabled" do
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
  registry_key({hive: 'HKEY_USERS'}).children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}\\[Ss][Oo][Ff][Tt][Ww][Aa][Rr][Ee]\\Policies\\Microsoft\\Windows\\Installer/).each do |entry|
    describe registry_key(entry) do
      its("AlwaysInstallElevated") { should cmp == 0 }
    end
  end
end
