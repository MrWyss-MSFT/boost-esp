#Requires -RunAsAdministrator
$PSDefaultParameterValues = @{
    "Install-ScheduledTask:Uri"               = "https://raw.githubusercontent.com/MrWyss-MSFT/boost-esp/main/Boost-ESP.ps1" # I highly recommend to host this file on your own
    "Install-ScheduledTask:TimeToLiveInHours" = 6
    "Install-ScheduledTask:Author"            = "MrWyss-MSFT"
    "Install-ScheduledTask:TaskName"          = "Boost-ESP"
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
        $TaskName

    )
    $OnlineScript = 'Invoke-Expression $($(Invoke-WebRequest -UseBasicParsing -Uri "' + $Uri + '").Content)'

    $Trigger = New-ScheduledTaskTrigger -AtStartup
    $User = "NT AUTHORITY\SYSTEM"
    $Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -NoLogo -NonInteractive -ExecutionPolicy Bypass -Command ""& {$OnlineScript}"""
    Register-ScheduledTask -TaskName $TaskName -Trigger $Trigger -User $User -Action $Action -RunLevel Highest -Force | out-null
    
    $TargetTask = Get-ScheduledTask -TaskName $TaskName 
    
    # Set desired tweaks
    $TargetTask.Author = $Author
    $TargetTask.Triggers[0].StartBoundary = [DateTime]::Now.ToString("yyyy-MM-dd'T'HH:mm:ss")
    $TargetTask.Triggers[0].EndBoundary = [DateTime]::Now.AddHours($TimeToLiveInHours).ToString("yyyy-MM-dd'T'HH:mm:ss")
    $TargetTask.Settings.AllowHardTerminate = $True
    $TargetTask.Settings.DeleteExpiredTaskAfter = 'PT0S'
    $TargetTask.Settings.ExecutionTimeLimit = 'PT1H'
    $TargetTask.Settings.volatile = $False
    
    # Save tweaks to the Scheduled Task
    $TargetTask | Set-ScheduledTask | Out-Null

}

Install-ScheduledTask