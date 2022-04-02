<#
  .SYNOPSIS
  Sets desired PowerMode and Sleep on AC Timeout to the desired Values while the device is in ESP

  .DESCRIPTION
  Gets Enrollment Status Page (ESP) status, if the device and user is in ESP it sets the PowerMode
  to whatever is specified in ($DesiredModeGuid) as well the sleep timeout on AC vallue to ($DesiredSleepTimeoutOnACInMinutes)
#>

#Requires -RunAsAdministrator

#region vars
$modes = @{ 
    # These power mode guid's may be different on some devices
    "Battery_saver_or_Recommended" = [guid] "00000000-0000-0000-0000-000000000000"
    "Better_performance"           = [guid] "3af9b8d9-7c97-431d-ad78-34a8bfea439f"
    "Best_performance"             = [guid] "ded574b5-45a0-4f42-8737-46345c09c238" 
}

$DesiredModeGuid = $modes.Best_performance.Guid
$DesiredSleepTimeoutOnACInMinutes = 0 
#$ScriptDirectory = Split-Path $MyInvocation.MyCommand.Path

$PSDefaultParameterValues = @{
    "*-Config:RegPath"        = "HKLM:\SOFTWARE\Boost-ESP"
    "Write-Log:Path"          = $env:ALLUSERSPROFILE + "\Microsoft\IntuneManagementExtension\Logs\Boost-Esp-$(Get-Date -Format yyyy-M-dd).log"
    "Write-Log:Component"     = "Boost-ESP"
    "Write-Log:Type"          = "Info"
    "Write-Log:ConsoleOutput" = $True
}
#endregion

#region powerprof.dll methods
#https://stackoverflow.com/questions/61869347/control-windows-10s-power-mode-programmatically
$function = @'
[DllImport("powrprof.dll", EntryPoint="PowerSetActiveOverlayScheme")]
public static extern int PowerSetActiveOverlayScheme(Guid OverlaySchemeGuid);
[DllImport("powrprof.dll", EntryPoint="PowerGetActualOverlayScheme")]
public static extern int PowerGetActualOverlayScheme(out Guid ActualOverlayGuid);
[DllImport("powrprof.dll", EntryPoint="PowerGetEffectiveOverlayScheme")]
public static extern int PowerGetEffectiveOverlayScheme(out Guid EffectiveOverlayGuid);
'@
$power = Add-Type -MemberDefinition $function -Name "Power" -PassThru -Namespace System.Runtime.InteropServices
#endregion

#region Functions
Function Write-Log {
    <#
    .SYNOPSIS
    Writes CMTrace log file, customized version of https://janikvonrotz.ch/2017/10/26/powershell-logging-in-cmtrace-format/
    #>

    [CmdletBinding()]
    Param(
        [parameter(Mandatory = $true)]
        [String]$Path,

        [parameter(Mandatory = $true, ValueFromPipeline)]
        [String]$Message,

        [parameter(Mandatory = $true)]
        [String]$Component,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Info", "Warning", "Error")]
        [String]$Type,
        
        [Parameter(Mandatory = $false)]
        [Switch]$ConsoleOutput
    )

    switch ($Type) {
        "Info" { [int]$Type = 1 }
        "Warning" { [int]$Type = 2 }
        "Error" { [int]$Type = 3 }
    }

    if ($ConsoleOutput.IsPresent) {
        switch ($Type) {
            1 { $ForgroundColor = "White" }
            2 { $ForgroundColor = "Yellow" }
            3 { $ForgroundColor = "Red" }
        }
        $OutPut = "{0} : {1}" -f $(Get-Date -Format "MM-d-yyyy HH:mm:ss.ffffff"), $Message
        write-host $OutPut -ForegroundColor $ForgroundColor
    }

    # Create a log entry
    $Content = "<![LOG[$Message]LOG]!>" + `
        "<time=`"$(Get-Date -Format "HH:mm:ss.ffffff")`" " + `
        "date=`"$(Get-Date -Format "M-d-yyyy")`" " + `
        "component=`"$Component`" " + `
        "context=`"$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " + `
        "type=`"$Type`" " + `
        "thread=`"$([Threading.Thread]::CurrentThread.ManagedThreadId)`" " + `
        "file=`"`">"

    # Write the line to the log file
    Add-Content -Path $Path -Value $Content
}
Function Get-PowerMode {
    <#
    .SYNOPSIS
    Gets the current power mode slide position returns name from $modes enum
    #>
    $effectiveOverlayGuid = [Guid]::NewGuid()
    $ret = $power::PowerGetEffectiveOverlayScheme([ref]$effectiveOverlayGuid)
    
    if ($ret -eq 0) {        
        return $($modes.GetEnumerator() | Where-Object { $_.value -eq $effectiveOverlayGuid })
    }
}
Function Get-PowerModeByGuid {
    <#
    .SYNOPSIS
    Gets the power mode name by given Guid and returns name from $modes enum
    #>
    param (
        [Parameter(Mandatory, HelpMessage = 'PowerMode Guid')]
        [guid]
        $Guid
    )
    return $($($modes.GetEnumerator() | Where-Object { $_.value -eq $Guid }).Key)
}
Function Set-PowerMode {
    <#
    .SYNOPSIS
    Sets power mode slider to the given power mode guid
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, HelpMessage = 'PowerMode Guid')]
        [guid]
        $Guid
    )
    try {
        $power::PowerSetActiveOverlayScheme($Guid) | Out-Null
    }
    catch {
        "An error occurred setting the PowerMode."
    }
}
Function Get-SleepTimeOutOnAC {
    <#
    .SYNOPSIS
    Uses powercfg /q scheme_GUID sub_GUID setting_GUID setting_index
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, HelpMessage = 'Power Scheme Guid')]
        [guid]
        $SchemeGuid
    )

    $TimeSpan = New-TimeSpan -Seconds (powercfg /q $SchemeGuid 238c9fa8-0aad-41ed-83f4-97be242c8f20 29f6c1db-86da-48c5-9fdb-f2b67b1f44da | Select-String -Pattern "Current AC Power Setting Index:").ToString().Split(":")[1]
    return $TimeSpan
}
function Set-SleepTimeOutOnAC {
    <#
    .SYNOPSIS
    Uses powercfg /change standby-timeout-ac $val
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, HelpMessage = 'Timeout in Minutes')]
        [int]
        $TimeOutInMinutes
    )
    powercfg /change standby-timeout-ac $TimeOutInMinutes
}
Function Get-CurrentPowerScheme {
    <#
    .SYNOPSIS
    Uses powercfg /GETACTIVESCHEME
    #>
    $power = [PSCustomObject]@{
        Name = (powercfg /GETACTIVESCHEME).split()[5]
        Guid = (powercfg /GETACTIVESCHEME).split()[3]
    }
    $power
}
Function Test-ESPCompleted {
    <#
    .SYNOPSIS
    Don't know if this is reliable
    #>
    param (
        [Parameter(Mandatory = $false)]
        [string]$UserSID
    )
    $RegPath = ""

    if ($UserSID -ne "") {
        $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking\{0}\Setup" -f $UserSID
        try {
            $val = Get-ItemPropertyValue -Path $RegPath -Name HasProvisioningCompleted -ErrorAction Stop 
            $val = '0x{0:x}‘ -f $val
            [bool][int32]$val
        }
        catch {
            $false
        }
    }
    else {
        $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking\Device\Setup"
        try {
            $val = Get-ItemPropertyValue -Path $RegPath -Name HasProvisioningCompleted -ErrorAction Stop
            $val = '0x{0:x}‘ -f $val
            [bool][int32]$val
        }
        catch {
            $Namespace = "root\cimv2\mdm\dmmap"
            $ClassName = "MDM_EnrollmentStatusTracking_Setup01"
            $ret = if ($(Get-CimInstance -Class $ClassName -Namespace $Namespace).HasProvisioningCompleted -eq "True") { $true } else { $false }
            return $ret
        }
    }
}
Function Save-Config {
    <#
    .SYNOPSIS
    Saves script specific Config to HKLM:\SOFTWARE\Boost-ESP
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, HelpMessage = 'PreScript sleep timeout on AC in Minutes')]
        [int]
        $PreScriptSleepTimeOutOnACInMinutes,
        [Parameter(Mandatory, HelpMessage = 'PreScript PowerMode Guid')]
        [guid]
        $PreScriptPowerModeGuid,
        [Parameter(Mandatory, HelpMessage = 'RegPath for the Settings')]
        [String]
        $RegPath
    )
    New-Item -Path $RegPath -Force | out-null
    Set-ItemProperty -Path $RegPath -Name PreScriptSleepTimeOutOnACInMinutes -Value $PreScriptSleepTimeOutOnACInMinutes -Force
    Set-ItemProperty -Path $RegPath -Name PreScriptPowerModeGuid -Value $PreScriptPowerModeGuid -Force
}
Function Get-Config {
    <#
    .SYNOPSIS
    Gets script specific Config from HKLM:\SOFTWARE\Boost-ESP
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, HelpMessage = 'Gets PreScript value')]
        [ValidateSet("PreScriptSleepTimeOutOnACInMinutes", "PreScriptPowerModeGuid")]
        [String]
        $PreScriptValue,
        [Parameter(Mandatory, HelpMessage = 'RegPath for the Settings')]
        [String]
        $RegPath
    )
    Get-ItemPropertyValue -Path $RegPath -Name $PreScriptValue
}
Function Test-Config {
    <#
    .SYNOPSIS
    Test if script specific Config from HKLM:\SOFTWARE\Boost-ESP exist
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, HelpMessage = 'Check if PreScript value exist')]
        [ValidateSet("PreScriptSleepTimeOutOnACInMinutes", "PreScriptPowerModeGuid")]
        [String]
        $PreScriptValue,
        [Parameter(Mandatory, HelpMessage = 'RegPath for the Settings')]
        [String]
        $RegPath
    )
    if (Test-Path -Path $RegPath) {
        if ($null -ne (Get-Item -Path $RegPath).GetValue($PreScriptValue)) {
            return $true
        }
    }
    else {
        $false
    }
}
Function Get-Loggedonuser {
    <#
    .SYNOPSIS
    Gets all logged on user, returns an array with psobjects
    ref: mjolinor 3/17/10, https://stackoverflow.com/questions/23219718/powershell-script-to-see-currently-logged-in-users-domain-and-machine-status
    #>
    $logontype = @{
        "0"  = "Local System"
        "2"  = "Interactive" #(Local logon)
        "3"  = "Network" # (Remote logon)
        "4"  = "Batch" # (Scheduled task)
        "5"  = "Service" # (Service account logon)
        "7"  = "Unlock" #(Screen saver)
        "8"  = "NetworkCleartext" # (Cleartext network logon)
        "9"  = "NewCredentials" #(RunAs using alternate credentials)
        "10" = "RemoteInteractive" #(RDP\TS\RemoteAssistance)
        "11" = "CachedInteractive" #(Local w\cached credentials)
    }
    
    $logon_sessions = @(Get-CimInstance -ClassName win32_logonsession)
    $logon_users = @(Get-CimInstance -ClassName win32_loggedonuser)
    
    $session_user = @{}
    
    $logon_users | ForEach-Object {
        $username = $_.Antecedent.Name
        $session = $_.dependent.LogonId
        $session_user[$session] += $username
    }
    
    $logon_sessions | ForEach-Object {
        $starttime = $_.StartTime
    
        $loggedonuser = New-Object -TypeName psobject
        $loggedonuser | Add-Member -MemberType NoteProperty -Name "Session" -Value $_.logonid
        $loggedonuser | Add-Member -MemberType NoteProperty -Name "User" -Value $session_user[$_.logonid]
        $loggedonuser | Add-Member -MemberType NoteProperty -Name "Type" -Value $logontype[$_.logontype.tostring()]
        $loggedonuser | Add-Member -MemberType NoteProperty -Name "Auth" -Value $_.authenticationpackage
        $loggedonuser | Add-Member -MemberType NoteProperty -Name "StartTime" -Value $starttime
        $loggedonuser
    }
    
}
Function Get-LoggedOnUserSID {
    <#
    .SYNOPSIS
    This function queries the registry to find the SID of the user that's currently logged onto the computer interactively.
    ref: https://adamtheautomator.com/powershell-get-user-sid/
    #>
    [CmdletBinding()]
    param ()
    
    process {
        try {
            New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS | Out-Null
            (Get-ChildItem HKU: | Where-Object { $_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$' }).PSChildName
        }
        catch {
            Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
            $false
        }
    }
}
Function Test-InESP {
    <#
    .SYNOPSIS
    Checks if device is in the enrollment status page (ESP).
    ref: https://www.reddit.com/r/Intune/comments/otpgnp/ps_app_deploy_toolkit_esp/
    #>
    $ESPCloudHost = @(Get-CimInstance -ClassName 'Win32_Process' -Filter "Name like 'CloudExperienceHostBroker.exe'" -ErrorAction 'SilentlyContinue')
    $ESPWWAHost = @(Get-CimInstance -ClassName 'Win32_Process' -Filter "Name like 'WWAHost.exe'" -ErrorAction 'SilentlyContinue')
    $ExplorerProcesses = @(Get-CimInstance -ClassName 'Win32_Process' -Filter "Name like 'explorer.exe'" -ErrorAction 'SilentlyContinue')
    $ESPCount = 0
    $ESPCount = $ESPCloudHost.Count + $ESPWWAHost.Count
    $InESP = $true
    if ($ExplorerProcesses.Count -eq 0 -Or $ESPCount -ne 0) {
        if ($ExplorerProcesses.Count -eq 0) {
            $InESP = $false
        }
        elseif ($ESPCount -ne 0) {
            $InESP = $true
        }
    }
    else {
        foreach ($TargetProcess in $ExplorerProcesses) {
            $Username = (Invoke-CimMethod -InputObject $TargetProcess -MethodName GetOwner).User
        }
    
        if ($UserName -ne 'defaultuser0') {
            $InESP = $false
        }
        else {
            $InESP = $true
        }
    }
    return $InESP
}
#endregion

#region logic
$CurrentPowerScheme = Get-CurrentPowerScheme
$CurrentPowerMode = Get-PowerMode
$CurrentSleepOnAC = Get-SleepTimeOutOnAC -SchemeGuid $CurrentPowerScheme.Guid

"----------------------------------------------------- Start Boost-ESP -----------------------------------------------------" | Write-Log
"LogFile Location  (use OneTrace)   : {0}" -f $PSDefaultParameterValues.'Write-Log:Path' | Write-Log
"RegPath Location                   : {0}" -f $PSDefaultParameterValues.'*-Config:RegPath' | Write-Log
"Time Zone                          : {0}" -f (Get-TimeZone | select-object DisplayName).DisplayName | Write-Log
"Last Bootup Time                   : {0}" -f (Get-CimInstance win32_operatingsystem | Select-Object lastbootuptime).lastbootuptime | Write-Log
"Device on AC (null = no battery)   : {0}" -f (Get-CimInstance -Namespace root/WMI -ClassName BatteryStatus -ErrorAction SilentlyContinue).PowerOnline | Write-Log
"Current Power Scheme Name          : {0}" -f ($CurrentPowerScheme.Name) | Write-Log
"Current Power Mode Name            : {0}" -f ($CurrentPowerMode.Name) | Write-Log
"Current Power Mode GUID            : {0}" -f ($CurrentPowerMode.Value) | Write-Log
"Current Sleep on AC Value (min)    : {0}" -f ($CurrentSleepOnAC.Minutes) | Write-Log
"Device ESP completed (unreliable)  : {0}" -f (Test-ESPCompleted).ToString() | Write-Log
"User ESP completed (unreliable)    : {0}" -f (Test-ESPCompleted -UserSID (Get-LoggedOnUserSID)).ToString() | Write-Log
"In ESP                             : {0}" -f (Test-InESP).ToString() | Write-Log -Type Warning
"List Logged On Users               : {0}" -f (Get-Loggedonuser | ConvertTo-Json) | Write-Log -ConsoleOutput:$false
"List running processes             : {0}" -f (Get-Process -IncludeUserName | Select-Object -Property  ProcessName, PriorityClass, UserName | ConvertTo-Json -EnumsAsStrings) | Write-Log -ConsoleOutput:$false

If ((Test-InESP)) {
    "Set Mode" | Write-log -Type Warning
    
    #region Set Power Mode
    "Current PowerMode Name             : {0}, Guid: {1}" -f $CurrentPowerMode.Name, $CurrentPowerMode.Value | Write-Log
    "Desired PowerMode                  : {0}, Guid: {1}" -f (Get-PowerModeByGuid -Guid $DesiredModeGuid), $DesiredModeGuid | Write-Log
    if ($CurrentPowerMode.Value -ne $DesiredModeGuid) {
        Set-PowerMode -Guid $DesiredModeGuid
        "  Set PowerMode to {0}" -f (Get-PowerModeByGuid -Guid $DesiredModeGuid) | Write-Log -Type Warning
    }
    else {
        "  No changes to PowerMode required" | Write-Log
    }
    #endregion

    #region Set Sleep
    "Current Sleep Timeout on AC (min)  : {0}" -f $CurrentSleepOnAC.Minutes | Write-Log 
    "Desired Sleep Timeout on AC (min)  : {0}" -f $DesiredSleepTimeoutOnACInMinutes | Write-Log
    if ($CurrentSleepOnAC.Minutes -ne $DesiredSleepTimeoutOnACInMinutes) {
        Set-SleepTimeOutOnAC -TimeOutInMinutes $DesiredSleepTimeoutOnACInMinutes
        "  Set Sleep Timeout on AC to {0} (min)" -f $DesiredSleepTimeoutOnACInMinutes | Write-Log -Type Warning
    }
    else {
        "  No changes to Sleep Timeout on AC required" | Write-Log
    }
    #endregion

    #region Save Config
    if ((Test-Config -PreScriptValue PreScriptPowerModeGuid) -eq $false) {
        "Save Config" | Write-Log -Type Warning
        Save-Config -PreScriptPowerModeGuid $CurrentPowerMode.Value -PreScriptSleepTimeOutOnACInMinutes $CurrentSleepOnAC.Minutes
    }
    else {
        "Config already saved" | Write-Log -Type Warning
    }
    #endregion
}
else {
    "Revert Mode" | Write-log -Type Warning

    #region Revert previously saved PowerMode if it was saved
    if (Test-Config -PreScriptValue "PreScriptPowerModeGuid") {
        "Revert back to previous PowerMode" | Write-Log -Type Warning
        $PreScriptPowerModeGuid = Get-Config -PreScriptValue "PreScriptPowerModeGuid"
        "  PreScript PowerMode Name was: {0}, Guid was: {1}" -f $(Get-PowerModeByGuid -Guid $PreScriptPowerModeGuid), $PreScriptPowerModeGuid | Write-Log
        Set-PowerMode -Guid $PreScriptPowerModeGuid
        "  Set PowerMode back to {0}" -f (Get-PowerModeByGuid -Guid $PreScriptPowerModeGuid) | Write-Log -Type Warning
    }
    else {
        "  PreScriptPowerModeGuid not found in registry" | Write-Log -Type Error
    }
    #endregion

    #region Revert previously saved Sleep timeout if it was saved
    if (Test-Config -PreScriptValue "PreScriptSleepTimeOutOnACInMinutes") {
        "Revert back to previous Sleep Timeout on AC Value" | Write-Log -Type Warning
        $PreScriptSleepTimeOutOnACInMinutes = Get-Config -PreScriptValue "PreScriptSleepTimeOutOnACInMinutes"
        "  PreScript Sleep Timeout on AC in (min) was: {0}" -f $PreScriptSleepTimeOutOnACInMinutes | Write-Log
        Set-SleepTimeOutOnAC -TimeOutInMinutes $PreScriptSleepTimeOutOnACInMinutes
        "  Set Sleep Timeout on AC back to {0} (min)" -f $PreScriptSleepTimeOutOnACInMinutes | Write-Log -Type Warning 
    }
    else {
        "  PreScriptSleepTimeOutOnACInMinutes not found in registry" | Write-Log -Type Error
    }
    #endregion
}
"------------------------------------------------------ End Boost-ESP ------------------------------------------------------" | Write-Log
#endregion logic