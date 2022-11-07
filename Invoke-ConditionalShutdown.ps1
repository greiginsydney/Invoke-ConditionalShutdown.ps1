<#
.SYNOPSIS
	This script shuts down (or hibernates) this server if various conditions are met

.DESCRIPTION
	
	
	

.NOTES
	Version				: 0.0
	Date				: 1st November 2022
	Author				: Greig Sheridan
	See the credits at the bottom of the script

	Based on :  
	Blog post:  

	WISH-LIST / TODO:

	KNOWN ISSUES:

	Revision History 	:
				v0.0 11th July 2020
					Initial release
				
					
.LINK
	
	https://greiginsydney.com/Invoke-ConditionalShutdown.ps1 - also https://github.com/greiginsydney/Invoke-ConditionalShutdown.ps1

.EXAMPLE
	.\Invoke-ConditionalShutdown.ps1

	Description
	-----------
	This executes a standard speed test against the default server for your location. Outputs to screen as XML (formatted for PRTG).
	The test results will be shown rounded to 3 decimal places.


.PARAMETER 
	String. 
	
.PARAMETER SkipList
	String. A comma-separated list of process names. If any on this list match a running process, the shutdown will be aborted.

.PARAMETER SkipFile
	File name (and path if you wish) of a file containing "skip conditions"

.PARAMETER Hibernate
	Switch. If present, the script will hibernate the machine instead of shutting it down
	
.PARAMETER Reopen
	Switch. If present, Windows will re-launch any open apps on the next boot
	
.PARAMETER TestMode
	Switch. If present, the script will NOT shutdown the machine. It's essentially a "whatif"

.PARAMETER Debug
	Switch. If present, the script will drop a detailed debug log file into its own folder. One per month.

#>

[CmdletBinding(SupportsShouldProcess = $False, DefaultParameterSetName='None')]
param(
	[Parameter(ParameterSetName='SetRegex', Mandatory = $true)]
	[switch]$SetRegexKey,
	[Parameter(ParameterSetName='ClearRegex', Mandatory = $true)]
	[switch]$ClearRegexKey,
	[Parameter(ParameterSetName='Default', Mandatory = $false)]
	[string]$SkipList,
	[Parameter(ParameterSetName='Default', Mandatory = $false)]
	[alias('File')][string]$SkipFile,
	[Parameter(ParameterSetName='Default', Mandatory = $false)]
	[switch]$Hibernate,
	[Parameter(ParameterSetName='Default', Mandatory = $false)]
	[switch]$Reopen,
	[Parameter(ParameterSetName='Default', Mandatory = $false)]
	[switch]$TestMode
)

$Error.Clear()		#Clear PowerShell's error variable
$Global:Debug = $psboundparameters.debug.ispresent


#--------------------------------
# START CONSTANTS ---------------
#--------------------------------

#--------------------------------
# END CONSTANTS -----------------
#--------------------------------

#--------------------------------
# START FUNCTIONS ---------------
#--------------------------------

function logme
{
	param ([string]$message, [bool]$display)

	if ($debug)
	{
		add-content -path $LogFile -value ('{0:MMMdd-HHmm} {1}' -f (get-date), $message) -force
	}
	if ($display)
	{
		write-output $message
	}
	
}

#--------------------------------
# END FUNCTIONS -----------------
#--------------------------------


$scriptpath = $MyInvocation.MyCommand.Path
$dir = Split-Path -Path $scriptpath
$Global:LogFile = (Join-Path -path $dir -childpath (("Invoke-ConditionalShutdown-{0:yyyyMMM}.log") -f (Get-Date)))

logme ''
logme 'Launched'

if ($SkipFile)
{
	#If the user only provided a filename, add the script's path for an absolute reference:
	if ([IO.Path]::IsPathRooted($SkipFile))
	{
		#It's absolute. Safe to leave.
	}
	else
	{
		#It's relative.
		$SkipFile = [IO.Path]::GetFullPath((Join-Path -path $dir -childpath $SkipFile))
	}
	logme ('$Skipfile is     "{0}"' -f $SkipFile)
}
else
{
	logme 'No $SkipFile provided.'
}


$params = ''

if ($Hibernate.IsPresent)
{
	if (!((Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Power -name HibernateEnabled -erroraction silentlycontinue).HibernateEnabled -eq 1))
	{
		logme ('Hibernate aborted: Hibernate is not enabled.') $true
		exit
	}
	$params += '-h '	# Hybernate doesn't want ANY more parameters!
}
else
{
	$params += "-t 20 -d P:0:0 -c 'Shutdown by script Invoke-ConditionalShutdown'"
	if ($Reopen.Ispresent)
	{
		$params += '-sg '
	}
	else
	{
		$params += '-s '
	}
}



$params = $params.trim()
write-host ("Params >" + $params + "<")
write-host ""

logme ('Params   = "{0}"' -f $params)

# Prep ends here. Now the real meat begins!

$shutdown = $true

$processes = get-process

foreach ($process in $processes)
{
	if ($skiplist -contains $process.name)
	{
		$shutdown = $false
		logme "Shutdown aborted: $($process.name) is running" $true
		break
	}
	
}

if ($shutdown)
{
	if (!$TestMode)
	{
		try
		{
			$response = Invoke-Expression "& shutdown $params"
			if (! [string]::IsNullOrEmpty($response))
			{
				logme "Response = $response" $true
			}
		}
		catch 
		{
			$result = "Error caught by handler: $_"
			logme $result $true
		}
	}
	else
	{
		if ($Hibernate.IsPresent)
		{
			logme "TestMode skipped what would have otherwise been a hibernate request" $true
		}
		else
		{
			logme "TestMode skipped what would have otherwise been a shutdown" $true
		}
	}
}

logme 'Exited cleanly.'

# CREDITS/REFERENCES:
# 'Shutdown': https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/shutdown
# ARSO: https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/winlogon-automatic-restart-sign-on-arso
# ARSO: https://www.elevenforum.com/t/enable-or-disable-auto-sign-in-and-lock-after-update-or-restart-in-windows-11.3324/
# Test for hibernate: https://stackoverflow.com/questions/41639739/get-hibernate-status
