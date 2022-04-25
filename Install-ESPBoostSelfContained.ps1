#Requires -RunAsAdministrator

#region Boost-ESP.ps1 v1.0.1-24-gcd3c515
$scheduledTaskScript = @'
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
$Debug = $false
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
$function = @"
[DllImport("powrprof.dll", EntryPoint="PowerSetActiveOverlayScheme")]
public static extern int PowerSetActiveOverlayScheme(Guid OverlaySchemeGuid);
[DllImport("powrprof.dll", EntryPoint="PowerGetActualOverlayScheme")]
public static extern int PowerGetActualOverlayScheme(out Guid ActualOverlayGuid);
[DllImport("powrprof.dll", EntryPoint="PowerGetEffectiveOverlayScheme")]
public static extern int PowerGetEffectiveOverlayScheme(out Guid EffectiveOverlayGuid);
"@
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
    $Content | Out-File -FilePath $Path -Append
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
    
    try {
        $TimeSpan = New-TimeSpan -Seconds (powercfg /q $SchemeGuid 238c9fa8-0aad-41ed-83f4-97be242c8f20 29f6c1db-86da-48c5-9fdb-f2b67b1f44da |  Select-Object -Last 3 | Select-Object -First 1).ToString().Split(":")[1]
        return $TimeSpan
    }
    catch {
        return $null
    }
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
    if ($false -eq (Test-Path -Path $RegPath)) { return $false }  
    if ($null -eq (Get-Item -Path $RegPath).GetValue($PreScriptValue)) { return $false }
    return $true
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
Function Test-InESP {
    <#
    .SYNOPSIS
    Checks if device is in the enrollment status page (ESP) Version 2
    heavily based on: https://www.reddit.com/r/Intune/comments/q8v92z/make_a_powershell_script_determine_if_it_is/
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, HelpMessage = 'DevicePreparationDetails PSCustomObject')]
        [AllowNull()] 
        [PSCustomObject]
        $DevicePreparationDetails,

        [Parameter(Mandatory, HelpMessage = 'DeviceSetupDetails PSCustomObject')]
        [AllowNull()] 
        [PSCustomObject]
        $DeviceSetupDetails,

        [Parameter(Mandatory, HelpMessage = 'AccountSetupDetails PSCustomObject')]
        [AllowNull()] 
        [PSCustomObject]
        $AccountSetupDetails,

        [Parameter(HelpMessage = 'SkipUserStatusPage boolean')]
        [bool]
        $SkipUserStatusPage = $false,

        [Parameter(HelpMessage = 'SkipDeviceStatusPage boolean')]
        [bool]
        $SkipDeviceStatusPage = $false
    )

    $DevicePrepComplete = $false
    $DeviceSetupCompleteOrSkipped = $false
    $AccountSetupCompleteOrSkipped = $false

    if (($DevicePreparationDetails -eq $null) -or ($AccountSetupDetails -eq $null) -or ($AccountSetupDetails -eq $null)) {
        return $false
    }

    if (($DevicePreparationDetails.categoryStatusText -eq 'Complete') -or ($DevicePreparationDetails.categoryState -eq 'succeeded')) {
        $DevicePrepComplete = $true
    }
    if (($DeviceSetupDetails.categoryStatusText -eq 'Complete') -or ($DeviceSetupDetails.categoryState -eq 'succeeded') -or $SkipDeviceStatusPage) {
        $DeviceSetupCompleteOrSkipped = $true
    }
    if (($AccountSetupDetails.categoryStatusText -eq 'Complete') -or ($AccountSetupDetails.categoryState -eq 'succeeded') -or $SkipUserStatusPage) {
        $AccountSetupCompleteOrSkipped = $true
    }
    
    
    if ($DevicePrepComplete -and $DeviceSetupCompleteOrSkipped -and $AccountSetupCompleteOrSkipped) {
        return $false
    }
    if (($DevicePreparationDetails.categoryState -like "failed*") -or ($DeviceSetupDetails.categoryState -like "failed*") -or ($AccountSetupDetails.categoryState -like "failed*")) {
        return $false
    }

    return $true
    
}
Function Get-ESPProgress () {
    <#
    .SYNOPSIS
    Reads the ESP Phase status from Registry, returns PSCustomObject
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, HelpMessage = 'Choose ESP Phase')]
        [ValidateSet("DevicePreparation", "DeviceSetup", "AccountSetup")]
        [String]
        $Phase
    )

    $RegPath = "HKLM:\SOFTWARE\Microsoft\Provisioning\AutopilotSettings"
    try {
        $val = Get-ItemPropertyValue -Path $RegPath -Name $Phase"Category.Status" -ErrorAction Stop
        return $val | ConvertFrom-Json
    }
    catch {
        $val = $null
    }
}
Function Get-SkipStatusPage () {
    <#
    .SYNOPSIS
    Reads the ESP Phase status from Registry, returns PSCustomObject
    #>
    [CmdletBinding(DefaultParameterSetName = 'user')]
    param (
        [Parameter(Mandatory, ParameterSetName = 'user', HelpMessage = 'SkipUserStatusPage')]
        [Switch]
        $User,
        [Parameter(Mandatory, ParameterSetName = 'device', HelpMessage = 'SkipDeviceStatusPage')]
        [Switch]
        $Device
    )
    
    try {
        $CurrentEnrollmentId = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Logger" -Name "CurrentEnrollmentId" -ErrorAction SilentlyContinue).CurrentEnrollmentId
        $path = "HKLM:\SOFTWARE\Microsoft\Enrollments\{0}\FirstSync" -f $CurrentEnrollmentId
        $key = "Skip{0}StatusPage" -f $($PSCmdlet.ParameterSetName)
        [bool][int32]$ret = "0x{0:x}" -f ((Get-ItemProperty -Path $path -Name $key -ErrorAction SilentlyContinue)."$key")
        return $ret
    }
    catch {
        return $false
    }
}
#endregion

#region logic
$TimeZone = (Get-TimeZone | select-object DisplayName).DisplayName
$LastBootupTime = (Get-CimInstance win32_operatingsystem | Select-Object lastbootuptime).lastbootuptime
$MaxClockSpeed = ((Get-CimInstance CIM_Processor).MaxClockSpeed)
$ProcessorPerformance = ((Get-Counter -Counter "\Processor Information(_Total)\% Processor Performance").CounterSamples.CookedValue)
$CurrentClockSpeed = ($MaxClockSpeed * ($ProcessorPerformance / 100))
$MemoryInfo = (Get-CIMInstance Win32_OperatingSystem | select-object TotalVisibleMemorySize, FreePhysicalMemory, @{Name = 'Usage'; Expression = { [int](($_.TotalVisibleMemorySize - $_.FreePhysicalMemory)) } })
$OnBattery = (Get-CimInstance -Namespace root/WMI -ClassName BatteryStatus -ErrorAction SilentlyContinue).PowerOnline
$CurrentPowerScheme = Get-CurrentPowerScheme
$CurrentPowerMode = Get-PowerMode
$CurrentSleepOnAC = Get-SleepTimeOutOnAC -SchemeGuid $CurrentPowerScheme.Guid
$SkipDeviceStatusPage = Get-SkipStatusPage -Device
$SkipUserStatusPage = Get-SkipStatusPage -User
$DevicePreparation = Get-ESPProgress -Phase DevicePreparation
$DeviceSetup = Get-ESPProgress -Phase DeviceSetup
$AccountSetup = Get-ESPProgress -Phase AccountSetup
$DOStatus = Get-DeliveryOptimizationStatus | Select-Object *
$InESP = Test-InESP -DevicePreparationDetails $DevicePreparation -DeviceSetupDetails $DeviceSetup -AccountSetupDetails $AccountSetup -SkipUserStatusPage $SkipUserStatusPage -SkipDeviceStatusPage $SkipDeviceStatusPage


"----------------------------------------------------- Start Boost-ESP -----------------------------------------------------" | Write-Log
"LogFile location  (use OneTrace)   : {0}" -f ($PSDefaultParameterValues.'Write-Log:Path') | Write-Log
"RegPath location                   : {0}" -f ($PSDefaultParameterValues.'*-Config:RegPath') | Write-Log
"Time Zone                          : {0}" -f ($TimeZone) | Write-Log
"Last Bootup Time                   : {0}" -f ($LastBootupTime) | Write-Log
"CPU Speed (mhz)                    : {0}" -f ([int]$CurrentClockSpeed) | Write-Log
"Total Memory (mb)                  : {0}" -f ([int]($MemoryInfo.TotalVisibleMemorySize / 1KB)) | Write-Log
"Usage Memory (mb)                  : {0}" -f ([int]($MemoryInfo.Usage / 1KB)) | Write-Log
"Free Memory (mb)                   : {0}" -f ([int]($MemoryInfo.FreePhysicalMemory / 1KB)) | Write-Log
"Device on AC (null = no battery)   : {0}" -f ($OnBattery) | Write-Log
"Current Power Scheme Name          : {0}" -f ($CurrentPowerScheme.Name) | Write-Log
"Current Power Mode Name            : {0}" -f ($CurrentPowerMode.Name) | Write-Log
"Current Power Mode Guid            : {0}" -f ($CurrentPowerMode.Value) | Write-Log
"Current Sleep on AC Value (min)    : {0}" -f ($CurrentSleepOnAC.Minutes) | Write-Log
"SkipDeviceStatusPage               : {0}" -f ($SkipDeviceStatusPage) | Write-Log
"SkipUserStatusPage                 : {0}" -f ($SkipUserStatusPage) | Write-Log
"DevicePreparation ESP phase status : {0}" -f ($DevicePreparation.categoryState) | Write-Log
"DeviceSetup ESP phase status       : {0}" -f ($DeviceSetup.categoryState) | Write-Log
"AccountSetup ESP phase status      : {0}" -f ($AccountSetup.categoryState) | Write-Log
"DevicePreparation full status      : {0}" -f ($DevicePreparation | ConvertTo-Json) | Write-Log -ConsoleOutput:$false
"DeviceSetup full status            : {0}" -f ($DeviceSetup | ConvertTo-Json) | Write-Log -ConsoleOutput:$false
"AccountSetup full status           : {0}" -f ($AccountSetup | ConvertTo-Json) | Write-Log -ConsoleOutput:$false
"DeliveryOptimization status        : {0}" -f ($DOStatus | ConvertTo-Json) | Write-Log -ConsoleOutput:$false
"In ESP                             : {0}" -f ($InESP) | Write-Log -Type Warning
if ($Debug) {
    "List logged on users               : {0}" -f (Get-Loggedonuser | ConvertTo-Json) | Write-Log -ConsoleOutput:$false
    "List running processes             : {0}" -f (Get-Process -IncludeUserName | Select-Object -Property ProcessName, PriorityClass, UserName | ConvertTo-Json) | Write-Log -ConsoleOutput:$false
}

If ($InESP) {
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

If (!$InESP) {
    "Revert Mode" | Write-log -Type Warning

    #region Revert previously saved PowerMode if it was saved
    if (Test-Config -PreScriptValue "PreScriptPowerModeGuid") {
        "Revert back to previous PowerMode" | Write-Log -Type Warning
        $PreScriptPowerModeGuid = Get-Config -PreScriptValue "PreScriptPowerModeGuid"
        "  PreScript PowerMode              : {0}, Guid was: {1}" -f $(Get-PowerModeByGuid -Guid $PreScriptPowerModeGuid), $PreScriptPowerModeGuid | Write-Log
        Set-PowerMode -Guid $PreScriptPowerModeGuid
        "  Revert PowerMode                 : {0}" -f (Get-PowerModeByGuid -Guid $PreScriptPowerModeGuid) | Write-Log -Type Warning
    }
    else {
        "  PreScriptPowerModeGuid not found in registry" | Write-Log -Type Error
    }
    #endregion

    #region Revert previously saved Sleep timeout if it was saved
    if (Test-Config -PreScriptValue "PreScriptSleepTimeOutOnACInMinutes") {
        "Revert back to previous Sleep Timeout on AC Value" | Write-Log -Type Warning
        $PreScriptSleepTimeOutOnACInMinutes = Get-Config -PreScriptValue "PreScriptSleepTimeOutOnACInMinutes"
        "  PreScript Sleep Timeout (min)    : {0}" -f $PreScriptSleepTimeOutOnACInMinutes | Write-Log
        Set-SleepTimeOutOnAC -TimeOutInMinutes $PreScriptSleepTimeOutOnACInMinutes
        "  Revert Sleep Timeout (min)       : {0}" -f $PreScriptSleepTimeOutOnACInMinutes | Write-Log -Type Warning 
    }
    else {
        "  PreScriptSleepTimeOutOnACInMinutes not found in registry" | Write-Log -Type Error
    }
    #endregion
}
"------------------------------------------------------ End Boost-ESP ------------------------------------------------------" | Write-Log
#endregion logic
'@
#endregion

$scheduledTaskScriptPath = "$env:CommonProgramW6432\Boost-ESP.ps1"
$scheduledTaskScript | out-file $scheduledTaskScriptPath

$PSDefaultParameterValues = @{
    "Install-ScheduledTask:TimeToLiveInHours"   = 6
    "Install-ScheduledTask:Author"              = "MrWyss-MSFT"
    "Install-ScheduledTask:TaskName"            = "Boost-ESP"
    "Install-ScheduledTask:RepetitionInterval"  = (New-TimeSpan -Minutes 5) 
    "Install-ScheduledTask:ScriptPath"          = $scheduledTaskScriptPath
}
Function Install-ScheduledTask {
    <#
    .SYNOPSIS
    Creates a scheduled task that run a online Powershell Script ($uri) on StartUp,
    Which expires after given hours ($TimeToLiveInHours)
    Optional an Author ($Author) can be specified for the Task
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, HelpMessage = 'Path to the PoSH Script to be run')]
        [string]
        $ScriptPath,
        [Parameter(Mandatory, HelpMessage = 'Specifies how long the task exists')]
        [int]
        $TimeToLiveInHours,
        [Parameter(HelpMessage = 'Author of the Scheduled Task')]
        [String]
        $Author,
        [Parameter(HelpMessage = 'Scheduled Task Name')]
        [String]
        $TaskName,
        [Parameter(HelpMessage = 'Repetition Duration, for how long')]
        [TimeSpan]
        $RepetitionDuration = ((New-TimeSpan -Hours $TimeToLiveInHours) - (New-TimeSpan -Minutes 2)),
        [Parameter(HelpMessage = 'Repetition Interval')]
        [TimeSpan]
        $RepetitionInterval,
        [Parameter(HelpMessage = 'Start task at startup')]
        [switch]
        $AtStartup

    )

    #$OnlineScript = 'Invoke-Expression $($(Invoke-WebRequest -UseBasicParsing -Uri "' + $Uri + '").Content)'
    $Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -NoLogo -NonInteractive -ExecutionPolicy Bypass -File ""$ScriptPath"""

    $Trigger = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddSeconds(10)) -RepetitionDuration $RepetitionDuration  -RepetitionInterva $RepetitionInterval
    $User = "NT AUTHORITY\SYSTEM"
   
    Register-ScheduledTask -TaskName $TaskName -Trigger $Trigger -User $User -Action $Action -RunLevel Highest -Force | out-null
    
    #region modify task 
    #get task
    $TargetTask = Get-ScheduledTask -TaskName $TaskName 
    #tweaks
    $TargetTask.Author = $Author
    $TargetTask.Triggers[0].StartBoundary = [DateTime]::Now.ToString("yyyy-MM-dd'T'HH:mm:ss")
    $TargetTask.Triggers[0].EndBoundary = [DateTime]::Now.AddHours($TimeToLiveInHours).ToString("yyyy-MM-dd'T'HH:mm:ss")
    $TargetTask.Settings.AllowHardTerminate = $True
    $TargetTask.Settings.DeleteExpiredTaskAfter = 'PT0S'
    $TargetTask.Settings.ExecutionTimeLimit = 'PT1H'
    $TargetTask.Settings.volatile = $False
    $TargetTask.Settings.DisallowStartIfOnBatteries = $False
    
    # Save tweaks
    $TargetTask | Set-ScheduledTask | Out-Null
    #endregion
}

Install-ScheduledTask
Start-ScheduledTask -TaskName $PSDefaultParameterValues.'Install-ScheduledTask:TaskName'
