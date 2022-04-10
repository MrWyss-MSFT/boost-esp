#Requires -RunAsAdministrator
$PSDefaultParameterValues = @{
    "Install-ScheduledTask:Uri"                 = "https://raw.githubusercontent.com/MrWyss-MSFT/boost-esp/main/Boost-ESP.ps1" # I highly recommend to host this file on your own
    "Install-ScheduledTask:TimeToLiveInHours"   = 6
    "Install-ScheduledTask:Author"              = "MrWyss-MSFT"
    "Install-ScheduledTask:TaskName"            = "Boost-ESP"
    "Install-ScheduledTask:RepetitionInterval"  = (New-TimeSpan -Minutes 5) 
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
        [Parameter(Mandatory, HelpMessage = 'web uri of the Script')]
        [string]
        $Uri,
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

    $OnlineScript = 'Invoke-Expression $($(Invoke-WebRequest -UseBasicParsing -Uri "' + $Uri + '").Content)'
    $Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -NoLogo -NonInteractive -ExecutionPolicy Bypass -Command ""& {$OnlineScript}"""

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