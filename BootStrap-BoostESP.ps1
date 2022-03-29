$ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/MrWyss-MSFT/boost-esp/main/Boost-ESP.ps1
Invoke-Expression $($ScriptFromGithHub.Content)