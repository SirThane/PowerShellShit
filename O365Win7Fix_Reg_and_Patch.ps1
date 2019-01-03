<# 
==========================================================================================================================
Copyright - PCC Metals Group

Script Name:    O365Win7Fix.ps1

Author:         Jerade Hensley, PCC Metals Group IT
Date:           12/28/2018

Comments:       This script is designed to address an issue with Legacy Authentication with Office 365.  It adds some
		        registry keys to force modern authentication, then downloads and installs Office patches. 

Resources:      www.microsoft.com

Last Modified:	Jerade Hensley
Date:           12/31/2018
Comments:       Check if update is installed. Only download absent updates.

Version:  	1.2
==========================================================================================================================
#>

$ActualVersion = $PSVersionTable.PSVersion.ToString()

# Invoke-WebRequest is available in PowerShell 3.0+
If ($PSVersionTable.PSVersion.Major -lt 3) {
    Write-Host "PowerShell Version less than 3.0 not usable"
    Write-Host "Version Actual: $ActualVersion"
    Exit
}

# Script can only run elevated. Self-elevation can only work on PowerShell 4.0+
# If run in PowerShell 3, will prompt to re-run from an elevated interpreter
# https://stackoverflow.com/questions/7690994/powershell-running-a-command-as-administrator
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    If ($PSVersionTable.PSVersion.Major -lt 4) {
        Write-Host "PowerShell version less than 4.0 cannot self-elevate"
        Write-Host "Run script from an elevated prompt"
        Write-Host "Actual Version: $ActualVersion"
        Exit
    }
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

Function Extract-KB {
    Param($KB)

    Process {
        # Extract HotFix; Wait for extraction to complete
        $ExtractProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
        $ExtractProcessInfo.FileName = $($KB.KBBin)
        $ExtractProcessInfo.Arguments = "/extract:$($KB.KBPath) /quiet"
        
        $ExtractProcess = New-Object System.Diagnostics.Process
        $ExtractProcess.StartInfo = $ExtractProcessInfo
        $ExtractProcess.Start() | Out-Null
        $ExtractProcess.WaitForExit()
    }
}

Function Verify-KB {
    Param($KB)

    Process {
        If (Test-Path $($KB.KBBin) -PathType Leaf) {
            $existingKBHash = Get-FileHash -Path $KB.KBBin -Algorithm MD5
            $existingKBHash = $existingKBHash.Hash
            If (!($($existingKBHash) -eq $($KB.KBMD5))) {
                Remove-Item $KB.KBBin
                Invoke-WebRequest -Uri $($KB.DL) -OutFile $($KB.KBBin)
                Extract-KB -KB $KB
            } Else {
                Extract-KB -KB $KB
            }
        } Else {
            Invoke-WebRequest -Uri $($KB.DL) -OutFile $($KB.KBBin)
            Extract-KB -KB $KB
        }
    }
}

Function Verify-MSP {
    Param($KB)

    Process {
        If (Test-Path $($KB.MSP) -PathType Leaf) {
            $existingMSPHash = Get-FileHash -Path $KB.MSP -Algorithm MD5
            $existingMSPHash = $existingMSPHash.Hash
            If (!($($existingMSPHash) -eq $($KB.MSPMD5))) {
                Remove-Item $KB.MSP
                Verify-KB -KB $KB
            } Else {
            return $true
            }
        } Else {
            Verify-KB -KB $KB
        }
    }
}

$MsiExecErrorCodes = @{
    0    = 'ERROR_SUCCESS';
    13   = 'ERROR_INVALID_DATA';
    87   = 'ERROR_INVALID_PARAMETER';
    120  = 'ERROR_CALL_NOT_IMPLEMENTED';
    1259 = 'ERROR_APPHELP_BLOCK';
    1601 = 'ERROR_INSTALL_SERVICE_FAILURE';
    1602 = 'ERROR_INSTALL_USEREXIT';
    1603 = 'ERROR_INSTALL_FAILURE';
    1604 = 'ERROR_INSTALL_SUSPEND';
    1605 = 'ERROR_UNKNOWN_PRODUCT';
    1606 = 'ERROR_UNKNOWN_FEATURE';
    1607 = 'ERROR_UNKNOWN_COMPONENT';
    1608 = 'ERROR_UNKNOWN_PROPERTY';
    1609 = 'ERROR_INVALID_HANDLE_STATE';
    1610 = 'ERROR_BAD_CONFIGURATION';
    1611 = 'ERROR_INDEX_ABSENT';
    1612 = 'ERROR_INSTALL_SOURCE_ABSENT';
    1613 = 'ERROR_INSTALL_PACKAGE_VERSION';
    1614 = 'ERROR_PRODUCT_UNINSTALLED';
    1615 = 'ERROR_BAD_QUERY_SYNTAX';
    1616 = 'ERROR_INVALID_FIELD';
    1618 = 'ERROR_INSTALL_ALREADY_RUNNING';
    1619 = 'ERROR_INSTALL_PACKAGE_OPEN_FAILED';
    1620 = 'ERROR_INSTALL_PACKAGE_INVALID';
    1621 = 'ERROR_INSTALL_UI_FAILURE';
    1622 = 'ERROR_INSTALL_LOG_FAILURE';
    1623 = 'ERROR_INSTALL_LANGUAGE_UNSUPPORTED';
    1624 = 'ERROR_INSTALL_TRANSFORM_FAILURE';
    1625 = 'ERROR_INSTALL_PACKAGE_REJECTED';
    1626 = 'ERROR_FUNCTION_NOT_CALLED';
    1627 = 'ERROR_FUNCTION_FAILED';
    1628 = 'ERROR_INVALID_TABLE';
    1629 = 'ERROR_DATATYPE_MISMATCH';
    1630 = 'ERROR_UNSUPPORTED_TYPE';
    1631 = 'ERROR_CREATE_FAILED';
    1632 = 'ERROR_INSTALL_TEMP_UNWRITABLE';
    1633 = 'ERROR_INSTALL_PLATFORM_UNSUPPORTED';
    1634 = 'ERROR_INSTALL_NOTUSED';
    1635 = 'ERROR_PATCH_PACKAGE_OPEN_FAILED';
    1636 = 'ERROR_PATCH_PACKAGE_INVALID';
    1637 = 'ERROR_PATCH_PACKAGE_UNSUPPORTED';
    1638 = 'ERROR_PRODUCT_VERSION';
    1639 = 'ERROR_INVALID_COMMAND_LINE';
    1640 = 'ERROR_INSTALL_REMOTE_DISALLOWED';
    1641 = 'ERROR_SUCCESS_REBOOT_INITIATED';
    1642 = 'ERROR_PATCH_TARGET_NOT_FOUND';
    1643 = 'ERROR_PATCH_PACKAGE_REJECTED';
    1644 = 'ERROR_INSTALL_TRANSFORM_REJECTED';
    3010 = 'ERROR_SUCCESS_REBOOT_REQUIRED'
}

Function Test-RegistryValue {
    # https://stackoverflow.com/questions/5648931/test-if-registry-value-exists
    Param(
        [Alias("PSPath")]
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [String]$Path
        ,
        [Parameter(Position = 1, Mandatory = $true)]
        [String]$Name
        ,
        [Switch]$PassThru
    ) 

    Process {
        if (Test-Path $Path) {
            $Key = Get-Item -LiteralPath $Path
            if ($Key.GetValue($Name, $null) -ne $null) {
                if ($PassThru) {
                    Get-ItemProperty $Path $Name
                } else {
                    $true
                }
            } else {
                $false
            }
        } else {
            $false
        }
    }
}

# HKEY_USERS needs to be added as a drive to be accessed.
New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | Out-Null

# HKU keys of this length are not the built-ins and can only be actual users. Don't want the _Classes aliases, either
$HKUs = Get-ChildItem -Path HKU: | where {$_.Name -notlike "*_Classes" -and $_.Name.Length -gt 20}

# Loop over the Users' keys to recursively add the keys needed. They aren't always there on some computers
ForEach ($HKU in $HKUs) {
    $HKUPath = $HKU.PSPath

    # If an intermediate key is missing, it doesn't add the parent keys. Have to add them key by key down the directory
    If (!(Test-Path "$HKUPath\Software\Microsoft\Exchange" -PathType Container)) {
        New-Item -Path "$HKUPath\Software\Microsoft\Exchange" | Out-Null
    }
    If (!(Test-Path "$HKUPath\Software\Microsoft\Office\15.0" -PathType Container)) {
        New-Item -Path "$HKUPath\Software\Microsoft\Office\15.0" | Out-Null
    }
    If (!(Test-Path "$HKUPath\Software\Microsoft\Office\15.0\Common" -PathType Container)) {
        New-Item -Path "$HKUPath\Software\Microsoft\Office\15.0\Common" | Out-Null
    }
    If (!(Test-Path "$HKUPath\Software\Microsoft\Office\15.0\Common\Identity" -PathType Container)) {
        New-Item -Path "$HKUPath\Software\Microsoft\Office\15.0\Common\Identity" | Out-Null
    }

    # ~~If the value is present, New-ItemProperty fails. If it is absent, Set-ItemProperty fails.~~
    # Stole some path testing code for registry values. Trying to cut down on error messages.
    If (Test-RegistryValue -Path "$HKUPath\Software\Microsoft\Exchange" -Name AlwaysUseMSOAuthForAutoDiscover) {
        Remove-ItemProperty -Path "$HKUPath\Software\Microsoft\Exchange" -Name AlwaysUseMSOAuthForAutoDiscover | Out-Null
    }
    New-ItemProperty -Path "$HKUPath\Software\Microsoft\Exchange" -Name AlwaysUseMSOAuthForAutoDiscover -Value 1 -PropertyType DWord | Out-Null
    
    If (Test-RegistryValue -Path "$HKUPath\Software\Microsoft\Office\15.0\Common\Identity" -Name EnableADAL) {
        Remove-ItemProperty -Path "$HKUPath\Software\Microsoft\Office\15.0\Common\Identity" -Name EnableADAL | Out-Null
    }
    New-ItemProperty -Path "$HKUPath\Software\Microsoft\Office\15.0\Common\Identity" -Name EnableADAL -Value 1 -PropertyType DWord | Out-Null
    
    If (Test-RegistryValue -Path "$HKUPath\Software\Microsoft\Office\15.0\Common\Identity" -Name Version) {
        Remove-ItemProperty -Path "$HKUPath\Software\Microsoft\Office\15.0\Common\Identity" -Name Version | Out-Null
    }
    New-ItemProperty -Path "$HKUPath\Software\Microsoft\Office\15.0\Common\Identity" -Name Version -Value 1 -PropertyType DWord | Out-Null
}

# Close all Office apps that could prevent updates from applying
$MSOApps = @("EXCEL.EXE", "OUTLOOK.EXE", "WORD.EXE", "POWERPNT.EXE", "WINWORD.EXE", "lync.exe", "lync99.exe", "ONENOTE.EXE", "ONENOTEM.EXE")
ForEach ($App in $MSOApps) {
    taskkill /f /im $App
}

$KBs = @()

$KBs += [PSCustomObject]@{
    ID     = 'KB3085565'
    DL     = 'https://download.microsoft.com/download/B/C/B/BCB2E69C-DB9E-43FE-9EC2-CBC40FFAF8F5/orgidcrl2013-kb3085565-fullfile-x86-glb.exe'
    KBBin  = 'C:\Windows\Temp\Win7O365Fix_KB3085565.exe'
    KBPath = 'C:\Windows\Temp\Win7O365Fix_KB3085565'
    MSP    = 'C:\Windows\Temp\Win7O365Fix_KB3085565\orgidcrl-x-none.msp'
    KBMD5  = '72C28513D0510457118A40B37C86005C'
    MSPMD5 = 'E62B406D9F5468C54D0472FA7B36E6C7'
}

$KBs += [PSCustomObject]@{
    ID     = 'KB4461556'
    DL     = 'https://download.microsoft.com/download/6/2/3/6232429E-271F-410A-BAA5-01B7C8351B71/outlook2013-kb4461556-fullfile-x86-glb.exe'
    KBBin  = 'C:\Windows\Temp\Win7O365Fix_KB4461556.exe'
    KBPath = 'C:\Windows\Temp\Win7O365Fix_KB4461556'
    MSP    = 'C:\Windows\Temp\Win7O365Fix_KB4461556\outlook-x-none.msp'
    KBMD5  = 'A3179CBE36FE6DCD0490B5C0858BF1DC'
    MSPMD5 = '0AD68EEDA6A79A1B45332F435B99F120'
}

$KBs += [PSCustomObject]@{
    ID     = 'KB4461486'
    DL     = 'https://download.microsoft.com/download/7/9/5/7951CE77-5E78-4A49-A767-B4DB1C413823/outlook2013-kb4461486-fullfile-x64-glb.exe'
    KBBin  = 'C:\Windows\Temp\Win7O365Fix_KB4461486.exe'
    KBPath = 'C:\Windows\Temp\Win7O365Fix_KB4461486'
    MSP    = 'C:\Windows\Temp\Win7O365Fix_KB4461486\outlook-x-none.msp'
    KBMD5  = '760DB03A33DD52DFAB120669676FACF2'
    MSPMD5 = 'CD9AC794E54ACE616A26770D91A38465'
}
$KBs += [PSCustomObject]@{
    ID     = 'KB4461482'
    DL     = 'https://download.microsoft.com/download/8/2/E/82EB0B8B-8BFC-484C-B83E-B83F499C6520/mso2013-kb4461482-fullfile-x86-glb.exe'
    KBBin  = 'C:\Windows\Temp\Win7O365Fix_KB4461482.exe'
    KBPath = 'C:\Windows\Temp\Win7O365Fix_KB4461482'
    MSP    = 'C:\Windows\Temp\Win7O365Fix_KB4461482\mso-x-none.msp'
    KBMD5  = 'FDC160317097C28B1A3C6FB4E6B4D8AC'
    MSPMD5 = 'D28823C2C648875BFD21BA4D72A5ECC6'
}

$KBs += [PSCustomObject]@{
    ID     = 'KB4461485'
    DL     = 'https://download.microsoft.com/download/7/4/4/7446E2EB-F1CC-435B-BA71-E26725B61085/word2013-kb4461485-fullfile-x86-glb.exe'
    KBBin  = 'C:\Windows\Temp\Win7O365Fix_KB4461485.exe'
    KBPath = 'C:\Windows\Temp\Win7O365Fix_KB4461485'
    MSP    = 'C:\Windows\Temp\Win7O365Fix_KB4461485\word-x-none.msp'
    KBMD5  = 'F63E9C5B9DA390CA323CB7CF0FC0EE02'
    MSPMD5 = '09E64083BFC743084701DBE00FD962EA'
}

$InstalledHotFixes = Get-HotFix | ForEach -Process {$_.HotFixID}

ForEach ($KB in $KBs) {

    # Check if HotFix is installed
    If (!($InstalledHotFixes.Contains($($KB.ID)))) {

        # Check for HotFix files
        Verify-MSP -KB $KB | Out-Null

        # Install extracted MSP update
        $ApplyUpdateProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
        $ApplyUpdateProcessInfo.FileName = "C:\Windows\System32\msiexec.exe"
        $ApplyUpdateProcessInfo.Arguments = "/update $($KB.MSP) /qn /l*v $($KB.KBPath)\install.log"

        $ApplyUpdateProcess = New-Object System.Diagnostics.Process
        $ApplyUpdateProcess.StartInfo = $ApplyUpdateProcessInfo
        $ApplyUpdateProcess.Start() | Out-Null
        $ApplyUpdateProcess.WaitForExit()

        Write-Host "HotFix $($KB.ID) exited with code $($ApplyUpdateProcess.ExitCode) ($($MsiExecErrorCodes.Item($($ApplyUpdateProcess.ExitCode))))"
    }
}