Thank you [posh-dsc-windowsserver-hardening](https://github.com/NVISOsecurity/posh-dsc-windows-hardening)


## Usage

To apply the CIS benchmark PowerShell DSC code, follow these steps in an elevated PowerShell prompt:

Install the required PowerShell DSC modules:

```
install-module AuditPolicyDSC
install-module ComputerManagementDsc
install-module SecurityPolicyDsc
```

Compile the CIS benchmark PowerShell DSC code:

```
./CIS_WindowsServer2016_v110.ps1
```

A MOF file will be created.

Increase the maximum envelope size, by running the following command

```
Set-Item -Path WSMan:\localhost\MaxEnvelopeSizeKb -Value 2048
```

Enable Windows Remote management:

```
winrm quickconfig
```

Run the following command to apply the PowerShell DSC configuration:

```
Start-DscConfiguration -Path .\CIS_WindowsServer2016_v110  -Force -Verbose -Wait
```

## CIS Microsoft Windows 10 Enterprise Release 1909 Benchmark v1.8.1

The file CIS_Windows10_v181.ps1 contains the Powershell DSC configuration applying the CIS Microsoft Windows 10 benchmark with the recommended controls.

The CIS benchmark is available on the following website:

[CIS Benchmarks - Center for Internet Security](https://www.cisecurity.org/cis-benchmarks/)

Please note the following exceptions:

* For control  5.39 (L2) Ensure 'Windows Remote Management (WS-Management) (WinRM)' is set to 'Disabled', modify to 2 for testing.

* For control  18.9.97.2.2 (L2) Ensure 'Allow remote server management through WinRM' is set to 'Disabled', modify to 1 for testing.

## CIS Microsoft Windows Server 2019 Release 1809 benchmark v1.1.0

The file CIS_WindowsServer2019_v110.ps1 contains the Powershell DSC configuration applying the CIS Microsoft Windows Server 2019 benchmark with the recommended controls.

The CIS benchmark is available on the following website:

[CIS Benchmarks - Center for Internet Security](https://www.cisecurity.org/cis-benchmarks/)

Please note the following exceptions:
* Some controls in chapter 2.2 (Local Policies: User Rights Assignment) are in comment due to duplicates.

* For control  18.9.97.2.2 (L2) Ensure 'Allow remote server management through WinRM' is set to 'Disabled', modify to 1 for testing.

* For control 19.7.41.1 (L1) Ensure 'Always install with elevated privileges' is set to 'Disabled', it is in comment because this is a duplicate of the control 18.9.85.2 (L1) Ensure 'Always install with elevated privileges' is set to 'Disabled'.

## CIS Microsoft Windows Server 2016 Release 1607 benchmark v1.1.0

The file CIS_WindowsServer2016_v110.ps1 contains the Powershell DSC configuration applying the CIS Microsoft Windows Server 2016 benchmark with the recommended controls.

The CIS benchmark is available on the following website:

[CIS Benchmarks - Center for Internet Security](https://www.cisecurity.org/cis-benchmarks/)

Please note the following exceptions:
* Some controls in chapter 2.2 (Local Policies: User Rights Assignment) are in comment due to duplicates.

* For control  18.9.97.2.2 (L2) Ensure 'Allow remote server management through WinRM' is set to 'Disabled', modify to 1 for testing.

* For control 19.7.40.1 (L1) Ensure 'Always install with elevated privileges' is set to 'Disabled', it is in comment because this is a duplicate of the recommendation control 18.9.85.2 (L1) Ensure 'Always install with elevated privileges' is set to 'Disabled'.


