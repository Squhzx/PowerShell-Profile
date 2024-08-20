### THIS FILE CONTAINS COMMANDS/FUNCTIONS THAT AUTORUN IN POWERSHELL STARTUP
### USE AS A $profile FILE

# Change powershell to only show current folder and drive letter
#function prompt 
#{
#   ( get-location ).drive.name + ":\" + "...\" + $( (get-item $pwd).Parent.Name ) + "\" + $( (get-item $pwd).Name ) +" > "
#}

## Secondary option for prompt using Oh My Posh
# NERD FONT REQUIRED
# Oh My Posh INSTALLATION REQUIRED
oh-my-posh init pwsh --config ~/jandedobbeleer.omp.json | Invoke-Expression


## Aliases

Set-Alias code code-insiders
Set-Alias wget wget2
Set-Alias py python
Set-Alias vim nvim
Set-Alias create touch
Set-Alias n notepad

## Functions
function cd...  { Set-Location ..\.. }
function cd.... { Set-Location ..\..\.. }
function dirs
{
    if ($args.Count -gt 0)
    {
        Get-ChildItem -Recurse -Include "$args" | Foreach-Object FullName
    }
    else
    {
        Get-ChildItem -Recurse | Foreach-Object FullName
    }
}
function admin
{
    if ($args.Count -gt 0)
    {
        $argsList = "& '" + $args + "'"
        Start-Process "$psHome\pwsh.exe" -Verb runAs -ArgumentList $argsList
    }
    else {
        Start-Process "$psHome\pwsh.exe" -Verb runAs
    }
}
function uptime
{
    $ts = (Get-Date) - (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
    $str = [string]::Format("{0} days, {1} hours, {2} minutes, {3} seconds",
        $ts.Days, $ts.Hours, $ts.Minutes, $ts.Seconds)
    $str
}
function find-file($name)
{
    Get-ChildItem -recurse -filter "*${name}*" -ErrorAction SilentlyContinue | select-object -expandproperty fullname
}
function touch($file) 
{
    "" | Out-File $file -Encoding ASCII
}
function which($name)
{
    Get-Command $name | Select-Object -ExpandProperty Definition
}
function pkill($name)
{
    Get-Process $name -ErrorAction SilentlyContinue | Stop-Process
}
function export ($name, $value)
{
    set-item -force -path env:$name -value $value
}

## Temporary variables
# Change 'CC' to 'gcc' for Mingw compatibility with Make
$env:CC = "gcc"


# Find out if the current user identity is elevated (has admin rights)
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal $identity
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# If so and the current host is a command line, then change to red color 
# as warning to user that they are operating in an elevated context
if (($host.Name -match "ConsoleHost") -and ($isAdmin))
{
     $host.UI.RawUI.BackgroundColor = "DarkRed"
     $host.PrivateData.ErrorBackgroundColor = "White"
     $host.PrivateData.ErrorForegroundColor = "DarkRed"
     Clear-Host
}

# We don't need these any more; they were just temporary variables to get to $isAdmin. 
# Delete them to prevent cluttering up the user profile. 
Remove-Variable identity
Remove-Variable principal