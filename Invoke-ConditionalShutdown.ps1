<#
.SYNOPSIS
	This script shuts down or hibernates this machine if one or more exceptions are NOT met.

.DESCRIPTION
	This script shuts down or hibernates this machine if one or more executables are running,
	or if specified text is NOT present in the title bar of a given app.
	
	

.NOTES
	Version				: 0.0
	Date				: 1st November 2022
	Author				: Greig Sheridan
	See the credits at the bottom of the script

	Based on : <null>
	Blog post: https://greiginsydney.com/Invoke-ConditionalShutdown.ps1

	WISH-LIST / TODO:

	KNOWN ISSUES:

	Revision History 	:
				v0.0 1st November 2022
					Initial release
				
					
.LINK
	https://greiginsydney.com/Invoke-ConditionalShutdown.ps1 - also https://github.com/greiginsydney/Invoke-ConditionalShutdown.ps1

.EXAMPLE
	.\Invoke-ConditionalShutdown.ps1

	Description
	-----------
	This initiates a system shutdown. It is no different to the "shutdown -t 10" command.

.EXAMPLE
	.\Invoke-ConditionalShutdown.ps1 -SkipList "Notepad++,Winword"

	Description
	-----------
	This initiates a system shutdown if Notepad++ and Winword are not running.

.EXAMPLE
	.\Invoke-ConditionalShutdown.ps1 -SkipFile "ShutdownSkipFile.csv"

	Description
	-----------
	This initiates a system shutdown if none of the tests in the "ShutdownSkipFile.csv" file pass. See documentation for the required file format.
	(It's basically "exe name", "title bar text", but with RegEx to complicate matters).

.EXAMPLE
	.\Invoke-ConditionalShutdown.ps1 -SetArsoKey 0

	Description
	-----------
	Sets the ARSO registry key to 0, enabling the -reopen attribute to operate as expected. See the reference link at the bottom of this file.

.EXAMPLE
	.\Invoke-ConditionalShutdown.ps1 -SkipFile "ShutdownSkipFile.csv" -TestMode

	Description
	-----------
	"-TestMode" is used when setting up the script. It validates your SkipList and SkipFile as appropriate, and does not shut down or hibernate the machine.
	If the machine would / would not shutdown or hiberate is output to the screen and log file.


.PARAMETER SkipList
	String. A comma-separated list of process names. If any on this list match a running process, the shutdown will be aborted.

.PARAMETER SkipFile
	File name (and path if you wish) of a file containing "skip conditions".

.PARAMETER Hibernate
	Switch. If present, the script will hibernate the machine instead of shutting it down.
	
.PARAMETER Reopen
	Switch. If present, Windows will re-launch any open apps on the next boot.
	
.PARAMETER GetArsoKey
	Switch. Queries the current state of the ARSO registry key.
	
.PARAMETER SetArsoKey
	Switch. Sets the ARSO registry key to 0, required for "-reopen" to operate correctly.
	
.PARAMETER TestMode
	Switch. If present, the script will NOT shutdown or hibernate the machine. It's essentially a "whatif".

.PARAMETER Debug
	Switch. If present, the script will drop a detailed debug log file into its own folder. One per month.

#>

[CmdletBinding(SupportsShouldProcess = $False, DefaultParameterSetName='None')]
param(
	[Parameter(ParameterSetName='GetRegistry', Mandatory = $true)]
	[switch]$GetArsoKey,
	[Parameter(ParameterSetName='SetRegistry', Mandatory = $true)]
	[ValidateRange(0,1)]
	[int]$SetArsoKey,

	[Parameter(ParameterSetName='Default', Mandatory = $false)]
	[string]$SkipList,
	[Parameter(ParameterSetName='Default', Mandatory = $false)]
	[alias('File')][string]$SkipFile,
	[Parameter(ParameterSetName='Default', Mandatory = $false)]
	[alias('h')][switch]$Hibernate,
	[Parameter(ParameterSetName='Default', Mandatory = $false)]
	[ValidateRange(0,315360000)]
	[alias('t')][int]$time=20,
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

$ArsoKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"


#--------------------------------
# END CONSTANTS -----------------
#--------------------------------

#--------------------------------
# START FUNCTIONS ---------------
#--------------------------------

function WriteRegistry
{
	param ([string]$Path, [string]$key, [string]$type, [string]$value)

	try
	{
		if (get-itemproperty -path $Path -name $key -ErrorAction Stop)
		{
			#It exists. Make sure it's set to 1
			Set-ItemProperty -Path $Path -name $key -Value $value -ErrorAction Stop | out-null
		}
		else
		{
			#Add it!
			New-ItemProperty -Path $Path -name $key -PropertyType $type -Value $value -ErrorAction Stop | out-null
		}
		switch ($value)
		{
			0 { logme 'Registry key value set to 0. AutomaticRestartSignOn is now ENABLED.' $true }
			1 { logme 'Registry key value set to 1. AutomaticRestartSignOn is now DISABLED.' $true }
		}
	}
	catch
	{
		if ($_.Exception -match "Requested registry access is not allowed")
		{
			logme "Requested registry access is not allowed" $true
		}
		else
		{
			$result = "Registry error caught by handler: $_"
			logme $result $true
		}
	}
}

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


if ($GetArsoKey.IsPresent -or $PSBoundParameters.ContainsKey("SetArsoKey"))
{
	if ($GetArsoKey.IsPresent)
	{
		$KeyValue = (Get-ItemProperty $ArsoKeyPath -name "DisableAutomaticRestartSignOn" -erroraction silentlycontinue).DisableAutomaticRestartSignOn
		switch ($keyvalue)
		{
			0       { logme 'Registry key value is 0. AutomaticRestartSignOn is ENABLED.' $true }
			1       { logme 'Registry key value is 1. AutomaticRestartSignOn is DISABLED.' $true }
			default { logme 'Registry key not found.' $true }
			
		}
	}
	else
	{
		# Set the key:
		WriteRegistry $ArsoKeyPath "DisableAutomaticRestartSignOn" "DWORD" $SetArsoKey
	}
	exit
}


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
	logme ('$SkipFile is     "{0}"' -f $SkipFile)
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
	$params += '-h'	# Hybernate doesn't want ANY more parameters!
}
else
{
	$params += "-t $($time) -d P:0:0 -c 'Shutdown by script Invoke-ConditionalShutdown'"
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
write-host ("Params >" + $params + "<") # DEBUG LINES. Remove before release!!
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
			$result = "Error caught by handler:`n$_"
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
