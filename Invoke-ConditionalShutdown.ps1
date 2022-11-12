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
	(It's basically "process name", "title bar text", but with RegEx to complicate matters).

.EXAMPLE
	.\Invoke-ConditionalShutdown.ps1 -SkipFile "ShutdownSkipFile.csv" -ValidateSkipFile

	Description
	-----------
	This validates the RegEx in your SkipFile without shutting down the system.

.EXAMPLE
	.\Invoke-ConditionalShutdown.ps1 -SetArsoKey

	Description
	-----------
	Sets the ARSO registry key, enabling the -reopen attribute to operate as expected. See the reference link at the bottom of this file.

.EXAMPLE
	.\Invoke-ConditionalShutdown.ps1 -SkipFile "ShutdownSkipFile.csv" -TestMode

	Description
	-----------
	"-TestMode" is used when setting up the script. If the machine would / would not shutdown or hiberate is output to the screen and log file.


.PARAMETER SkipList
	String. A comma-separated list of process names. If any on this list match a running process, the shutdown will be aborted.

.PARAMETER SkipFile
	File name (and path if you wish) of a file containing "skip conditions".

.PARAMETER ValidateSkipFile
	Switch. If present, the script will test the validity of the Regular Expressions in the SkipFile

.PARAMETER Hibernate
	Switch. If present, the script will hibernate the machine instead of shutting it down.
	
.PARAMETER Reopen
	Switch. If present, Windows will re-launch any open apps on the next boot.
	
.PARAMETER GetArsoKey
	Switch. Queries the current state of the ARSO registry key.
	
.PARAMETER SetArsoKey
	Switch. Sets the ARSO registry key to 0 or 1. A value of 0 is required for "-reopen" to operate correctly.
	
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
	[switch]$ValidateSkipFile,
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


function ValidateSkipFile
{
	param ([string]$Filename)

	$SkipFileEntries = $null

	#If the user only provided a filename, add the script's path for an absolute reference:
	if ([IO.Path]::IsPathRooted($Filename))
	{
		#It's absolute. Safe to leave.
	}
	else
	{
		#It's relative.
		$Filename = [IO.Path]::GetFullPath((Join-Path -path $dir -childpath $Filename))
	}

	if (test-path $Filename)
	{
		#OK, the SkipFile exists.
		logme ('SkipFile is "{0}"' -f $Filename) $true $true
		$SkipFileEntries = import-csv $Filename
		#Check if SkipFile file is empty:
		if ($SkipFileEntries -ne $null)
		{
			#OK, it's not empty. (It has at least headers).
			#Let's check it has the RIGHT headers:
			$FileValid = 0
			foreach ($columnTitle in $SkipFileEntries[0].psobject.properties.name)
			{
				if (@('Name','TitleBar') -contains $columnTitle) { $fileValid ++ }
			}
			if ($fileValid -eq 2)
			{
				#It has the expected headers. Now check for at least one entry:
				$count = $SkipFileEntries | Measure-Object | Select-Object -expand count
				if ($count -eq 0)
				{
					logme "SkipFile contains nothing to skip!" $true $true
				}
				else
				{
					#So far so good. Now is the RegEx valid?
					if ($ValidateSkipfile.IsPresent) # (We don't bother with this step otherwise. The script will skip over bad RegEx when it executes)
					{
						$SkipFileEntryId = 1
						foreach ($SkipFileEntry in $SkipFileEntries)
						{
							if (ValidateRegex $SkipFileEntry.Name)
							{
								logme ("Entry #{0} Name     is valid: {1}" -f $SkipFileEntryId, ($SkipFileEntry.Name).PadRight(1,"-")) $true $true
							}
							else
							{
								logme ("Entry #{0} Name     is bad  : {1}" -f $SkipFileEntryId, $RegexError) $true $true
							}
							if (ValidateRegex $SkipFileEntry.TitleBar)
							{
								logme ("Entry #{0} TitleBar is valid: {1}" -f $SkipFileEntryId, ($SkipFileEntry.TitleBar).PadRight(1,"-")) $true $true
							}
							else
							{
								logme ("Entry #{0} TitleBar is bad  : {1}" -f $SkipFileEntryId, $RegexError) $true $true
							}
							$SkipFileEntryId ++
						}
					}
				}
			}
			else
			{
				#Bad headers. Null the content and drop an error:
				$SkipFileEntries = $null
				logme "Skipfile doesn't contain the required headers." $true $true
			}
		}
		else
		{
			logme "SkipFile is empty" $true $true
		}
	}
	else
	{
		logme ('SkipFile "{0}" does not exist.' -f $Filename) $true $true
	}
	
	return $SkipFileEntries
}


function ValidateRegex
{
	param ([string]$regex)

	if ([string]::IsNullOrEmpty($regex)) { return $true }
	try
	{
		("" -match $regex)
		return $true
	}
	catch
	{
		$Global:RegexError = $_.Exception.Message
		return $false
	}
}


function logme
{
	param ([string]$message, [bool]$display = $false, [bool]$ForceLog = $false)

	if ($debug -or $ForceLog)
	{
		add-content -path $LogFile -value ('{0:MMMdd-HHmm} {1}' -f (get-date), $message) -force
	}
	if ($display)
	{
		#The need for 'write-information' is because ValidateFile returns a value, and as such it would have prevented write-output from working in the nested calls to logme.
		if ($PSVersionTable.PSVersion.Major -ge 5)
		{
			Write-Information -MessageData $message -InformationAction continue
		}
		else
		{
			# SURELY no-one's running anything lower than v5?
			write-host $message
		}
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
	logme 'Exited after Registry interaction.'
	exit
}


if ($SkipFile)
{
	$SkipFileEntries = validateSkipFile $SkipFile
}
else
{
	logme 'No $SkipFile provided.'
	$SkipFileEntries = $null
}

if ($ValidateSkipFile.IsPresent)
{
	logme 'Exited after validating SkipFile.'
	exit
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
logme ('Params = "{0}"' -f $params) $false

# Prep ends here. Now the real meat begins!


$shutdown = $true

:outer foreach ($process in get-process)
{
	if ($skiplist -contains $process.Name)
	{
		$shutdown = $false
		logme "Shutdown aborted: $($process.name) is running" $true $true
		break
	}
	$SkipFileEntryId = 1
	foreach ($SkipFileEntry in $SkipFileEntries)
	{
		if ((ValidateRegex $SkipFileEntry.Name) -and (ValidateRegex $SkipFileEntry.TitleBar))
		{
			if (($Process.Name -match $SkipFileEntry.Name)`
				-and ($Process.mainWindowTitle -match $SkipFileEntry.TitleBar))
			{
				$shutdown = $false
				logme ("Shutdown aborted: {0} / {1} matches SkipFile entry #{2}" -f ($process.name).PadRight(1,"-"), ($Process.mainWindowTitle).PadRight(1,"-"), $SkipFileEntryId) $true $true
				break outer
			}
		}
		$SkipFileEntryId ++
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
# Get-Process (including Window titles): https://devblogs.microsoft.com/scripting/powertip-display-titles-of-windows/
# 											Get-Process | Where { $_.MainWindowTitle} |Select-Object ProcessName, MainWindowTitle
# Shutdown: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/shutdown
# ARSO: https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/winlogon-automatic-restart-sign-on-arso
# ARSO: https://www.elevenforum.com/t/enable-or-disable-auto-sign-in-and-lock-after-update-or-restart-in-windows-11.3324/
# Test for hibernate: https://stackoverflow.com/questions/41639739/get-hibernate-status
# The registry writes: https://github.com/greiginsydney/Set-SfBClientWarnings.ps1/blob/master/Set-SfBClientWarnings.ps1
