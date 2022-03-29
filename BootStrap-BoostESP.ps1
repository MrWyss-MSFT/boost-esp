$ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/MrWyss-MSFT/boost-esp/main/BootStrap-BoostESP.ps1
Invoke-Expression $($ScriptFromGithHub.Content)