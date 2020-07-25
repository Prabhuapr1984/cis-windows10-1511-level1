
# cis-windows10-1511-level1

Chef Inspec profile for windows 10 CIS Level 1 standards.

## Description

The CIS profile guide can be download from [CIS](https://downloads.cisecurity.org/)

## Pre-requisites

* Chef Inspec or ChefDK or Chef Workstation(which is recently released by chef) [Chef](https://downloads.chef.io/)
* WinRM Enabled (To run inspec on remote servers: https://docs.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management)

### Supported OS Platform

- Windows 10

### Profile section details:

    - section_1  : Password Policy
    - section_2  : Local Policies
    - section_9  : Windows Firewall
    - section_17 : Audit Policies
    - section_18 : [Excluded EMET settings which is deprecated by Microsoft, so i have excluded those settings]
    - section_19 : [User Settings: Not really mandatory and can be excluded if you want]

## Usage

```
# run inspec profile locally without downloading and directly from Github
$ inspec exec https://github.com/Prabhuapr1984/cb-cis-level1-windows10-1511

# clone the profile from GitHub and run locally
$ git clone https://github.com/Prabhuapr1984/cb-cis-level1-windows10-1511
$ inspec exec cis-level1-windows2016-member

# run inspec profile on remote node
inspec exec https://github.com/Prabhuapr1984/cb-cis-level1-windows10-1511 -t winrm://<ip-address/hostname>:5985 --user=<username> --password=<password>

```
### Excluded Controls:
    - xccdf_org.cisecurity.benchmarks_rule_2.3.1.1_L1_Ensure_Accounts_Administrator_account_status_is_set_to_Disabled

    - xccdf_org.cisecurity.benchmarks_rule_2.3.1.3_L1_Ensure_Accounts_Guest_account_status_is_set_to_Disabled

    - xccdf_org.cisecurity.benchmarks_rule_2.3.1.5_L1_Configure_Accounts_Rename_administrator_account

    - xccdf_org.cisecurity.benchmarks_rule_2.3.1.6_L1_Configure_Accounts_Rename_guest_account

    - xccdf_org.cisecurity.benchmarks_rule_18.9.22.1_L1_Ensure_EMET_5.5_or_higher_is_installed

    - xccdf_org.cisecurity.benchmarks_rule_18.9.22.2_L1_Ensure_Default_Action_and_Mitigation_Settings_is_set_to_Enabled_plus_subsettings

    - xccdf_org.cisecurity.benchmarks_rule_18.9.22.3_L1_Ensure_Default_Protections_for_Internet_Explorer_is_set_to_Enabled

    - xccdf_org.cisecurity.benchmarks_rule_18.9.22.4_L1_Ensure_Default_Protections_for_Popular_Software_is_set_to_Enabled

    - xccdf_org.cisecurity.benchmarks_rule_18.9.22.5_L1_Ensure_Default_Protections_for_Recommended_Software_is_set_to_Enabled

    - xccdf_org.cisecurity.benchmarks_rule_18.9.22.6_L1_Ensure_System_ASLR_is_set_to_Enabled_Application_Opt-In

    - xccdf_org.cisecurity.benchmarks_rule_18.9.22.7_L1_Ensure_System_DEP_is_set_to_Enabled_Application_Opt-Out

    - xccdf_org.cisecurity.benchmarks_rule_18.9.22.8_L1_Ensure_System_SEHOP_is_set_to_Enabled_Application_Opt-Out

## Contributors

* Prabu Jaganathan [Prabhuapr1984](https://github.com/Prabhuapr1984) 