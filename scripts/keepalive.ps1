[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')]
    [string] $Distribution,
    [switch] $NoRegister
)

$ErrorActionPreference = 'Stop'
$TaskName = 'Private-Deployment-Controller'
# Task Scheduler passes these arguments directly to wsl.exe. Quoting this
# no-space, regex-validated distribution name makes WSL treat the quotes as
# part of its name in that context (WSL_E_DISTRO_NOT_FOUND).
$TaskArguments = '--distribution {0} --exec /usr/bin/sleep infinity' -f $Distribution

if ($NoRegister) {
    [pscustomobject]@{
        task_name = $TaskName
        distribution = $Distribution
        executable = 'wsl.exe'
        arguments = @('--distribution', $Distribution, '--exec', '/usr/bin/sleep', 'infinity')
        argument_string = $TaskArguments
        logon_type = 'Interactive'
        run_level = 'Limited'
        restart_seconds = 60
        execution_time_limit_seconds = 0
    } | ConvertTo-Json -Depth 3
    exit 0
}

$Wsl = Join-Path $env:SystemRoot 'System32\wsl.exe'
# Interactive, limited privileges keep this scoped to the signed-in operator.
# No machine-specific identity or filesystem location is stored in this file.
$Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
# Use the native scheduler COM API, independent of the optional CIM namespace.
$Scheduler = New-Object -ComObject 'Schedule.Service'
$Scheduler.Connect()
$Folder = $Scheduler.GetFolder('\')
$Task = $Scheduler.NewTask(0)
$Task.RegistrationInfo.Description = 'Keep the private deployment controller distribution running while the operator is signed in.'
$Task.Principal.UserId = $Identity
$Task.Principal.LogonType = 3 # TASK_LOGON_INTERACTIVE_TOKEN
$Task.Principal.RunLevel = 0 # TASK_RUNLEVEL_LUA (limited)
$Task.Settings.Enabled = $true
$Task.Settings.AllowDemandStart = $true
$Task.Settings.ExecutionTimeLimit = 'PT0S'
$Task.Settings.RestartCount = 999
$Task.Settings.RestartInterval = 'PT1M'
$Task.Settings.MultipleInstances = 2 # TASK_INSTANCES_IGNORE_NEW
$Task.Settings.StartWhenAvailable = $true
$Task.Settings.DisallowStartIfOnBatteries = $false
$Task.Settings.StopIfGoingOnBatteries = $false
$Trigger = $Task.Triggers.Create(9) # TASK_TRIGGER_LOGON
$Trigger.Enabled = $true
$Trigger.UserId = $Identity
$Action = $Task.Actions.Create(0) # TASK_ACTION_EXEC
$Action.Path = $Wsl
$Action.Arguments = $TaskArguments
$Registered = $Folder.RegisterTaskDefinition(
    $TaskName, $Task, 6, $Identity, $null, 3, $null # CREATE_OR_UPDATE, interactive token
)
$null = $Registered.Run($null)
Write-Output 'deployment_keepalive_registered'
