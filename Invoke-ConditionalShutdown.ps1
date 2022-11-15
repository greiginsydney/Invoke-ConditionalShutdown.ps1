<#
.SYNOPSIS
	This script shuts down or hibernates this machine provided NONE of the listed exceptions are met.

.DESCRIPTION
	This script shuts down or hibernates this machine provided NONE of the listed exceptions are met.
	The listed exceptions can be a comma-separated list of process names, or a CSV file containing process names
	 and matching title bar text. The CSV file values are all interpreted as Regular Expressions, allowing a
	 more granular level of control.

	Command-line switches also allow the user to query, set and clear the Registry Key for the
	 "automatic restart sign on" (ARSO) feature (subject to Windows permissions of course).

	A log file is created that captures each time the script runs. To see this info on-screen add the '-verbose' switch.



.NOTES
	Version				: 1.0
	Date				: 15th November 2022
	Author				: Greig Sheridan
	See the credits at the bottom of the script

	Based on : <null>
	Blog post: https://greiginsydney.com/Invoke-ConditionalShutdown.ps1

	WISH-LIST / TODO:	Add the ability to skip a shutdown if there's a remote user session open/disconnected, or other users logged in.

	KNOWN ISSUES:

	Revision History 	:
				v1.0 15th November 2022
					Initial release

.LINK
	https://greiginsydney.com/Invoke-ConditionalShutdown.ps1 - also https://github.com/greiginsydney/Invoke-ConditionalShutdown.ps1

.EXAMPLE
	.\Invoke-ConditionalShutdown.ps1

	Description
	-----------
	Displays the script's examples. If you're running the script with no parameters you're doing it wrong.

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
	(It's basically "process name"<comma>"title bar text" but with RegEx to complicate matters).

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


#--------------------------------
# START CONSTANTS ---------------
#--------------------------------

$ArsoKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$Global:Verbose = $psboundparameters.verbose.ispresent

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
			logme $result $true $true
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
		logme ('SkipFile is "{0}"' -f $Filename) $false $true
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
					#So far so good.
					#Fix crazy edge case: if the LAST TitleBar in the file is blank, it's read as a null and breaks the display below:
					$SkipFileEntries = ($SkipFileEntries | Select Name,@{N = 'TitleBar'; E = {if([string]::IsNullOrEmpty($_.TitleBar)) { "" } else { $_.TitleBar }}})
					#Now is the RegEx valid?
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
	param ([string]$Message, [bool]$Display = $false)

	add-content -path $LogFile -value ('{0:MMMdd-HHmm} {1}' -f (get-date), $Message) -force

	if ($Display -or $Verbose)
	{
		#The need for 'write-information' is because ValidateFile returns a value, and as such it would have prevented write-output from working in the nested calls to logme.
		if ($PSVersionTable.PSVersion.Major -ge 5)
		{
			Write-Information -MessageData $Message -InformationAction continue
		}
		else
		{
			# SURELY no-one's running anything lower than v5?
			write-host $Message
		}
	}
}

#--------------------------------
# END FUNCTIONS -----------------
#--------------------------------


$ScriptPath = $MyInvocation.MyCommand.Path
$ScriptName = $MyInvocation.MyCommand.Name
$dir = Split-Path -Path $ScriptPath
$Global:LogFile = (Join-Path -path $dir -childpath (("Invoke-ConditionalShutdown-{0:yyyyMMM}.log") -f (Get-Date)))


[string]$ParamList = ""
foreach($boundparam in $PSBoundParameters.GetEnumerator())
{
	[string]$ParamList += "{0}={1} " -f $boundparam.Key,$boundparam.Value
}
$ParamList = $ParamList.trim()

if ([string]::IsNullOrEmpty($ParamList))
{
	get-help .\$($ScriptName) -examples
	exit
}


logme '' $false
logme ('Launched with: {0}' -f $ParamList.PadRight(1,"-")) $false


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
	logme 'Exited after Registry interaction.' $false
	exit
}


if ($SkipFile)
{
	$SkipFileEntries = validateSkipFile $SkipFile
}
else
{
	logme 'No $SkipFile provided.' $false
	$SkipFileEntries = $null
}

if ($ValidateSkipFile.IsPresent)
{
	logme 'Exited after validating SkipFile.' $false
	exit
}


$params = ''

if ($Hibernate.IsPresent)
{
	if (!((Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Power -name HibernateEnabled -erroraction silentlycontinue).HibernateEnabled -eq 1))
	{
		logme 'Hibernate aborted: Hibernate is not enabled.' $true
		exit
	}
	$params += '-h'	# Hybernate doesn't want ANY more parameters!
}
else
{
	$params += "-t $($time) -d P:0:0 -c 'Shutdown by script Invoke-ConditionalShutdown' "
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
	$SkipListArray = ($SkipList).Split(',')
	if ($SkipListArray -contains $process.Name)
	{
		$shutdown = $false
		logme "Shutdown aborted: $($process.name) is running" $true
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
				logme ("Shutdown aborted: {0} / {1} matches SkipFile entry #{2}" -f ($process.name).PadRight(1,"-"), ($Process.mainWindowTitle).PadRight(1,"-"), $SkipFileEntryId) $true
				break outer
			}
		}
		$SkipFileEntryId ++
	}
}

if ($shutdown)
{
	if ($TestMode.IsPresent)
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
	else
	{
		try
		{
			$response = Invoke-Expression "& shutdown $params"
			if ([string]::IsNullOrEmpty($response))
			{
				if ($Hibernate.IsPresent)
				{
					logme "Hibernate invoked" $true
				}
				else
				{
					logme "Shutdown invoked" $true
				}
			}
			else
			{
				logme "Response = $response" $false $true
			}
		}
		catch
		{
			$result = "Error caught by handler:`n$_"
			logme $result $true
		}
	}
}

logme 'Exited cleanly.' $false

# CREDITS/REFERENCES:
# Get-Process (including Window titles): https://devblogs.microsoft.com/scripting/powertip-display-titles-of-windows/
# 											Get-Process | Where { $_.MainWindowTitle} |Select-Object ProcessName, MainWindowTitle
# Shutdown: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/shutdown
# ARSO: https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/winlogon-automatic-restart-sign-on-arso
# ARSO: https://www.elevenforum.com/t/enable-or-disable-auto-sign-in-and-lock-after-update-or-restart-in-windows-11.3324/
# Test for hibernate: https://stackoverflow.com/questions/41639739/get-hibernate-status
# The registry writes: https://github.com/greiginsydney/Set-SfBClientWarnings.ps1/blob/master/Set-SfBClientWarnings.ps1

# Crazy Edge case: https://github.com/PowerShell/PowerShell/issues/17702
# Fix for above: https://stackoverflow.com/questions/66495269/how-to-replace-a-null-or-empty-value-in-powershell

#Code-signing cert with thanks to Digicert:

# SIG # Begin signature block
# MIIn/wYJKoZIhvcNAQcCoIIn8DCCJ+wCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUzk8o/EKz19y0WBcJYsy+abE9
# uUmggiEnMIIFjTCCBHWgAwIBAgIQDpsYjvnQLefv21DiCEAYWjANBgkqhkiG9w0B
# AQwFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVk
# IElEIFJvb3QgQ0EwHhcNMjIwODAxMDAwMDAwWhcNMzExMTA5MjM1OTU5WjBiMQsw
# CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
# ZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC/5pBzaN675F1KPDAiMGkz
# 7MKnJS7JIT3yithZwuEppz1Yq3aaza57G4QNxDAf8xukOBbrVsaXbR2rsnnyyhHS
# 5F/WBTxSD1Ifxp4VpX6+n6lXFllVcq9ok3DCsrp1mWpzMpTREEQQLt+C8weE5nQ7
# bXHiLQwb7iDVySAdYyktzuxeTsiT+CFhmzTrBcZe7FsavOvJz82sNEBfsXpm7nfI
# SKhmV1efVFiODCu3T6cw2Vbuyntd463JT17lNecxy9qTXtyOj4DatpGYQJB5w3jH
# trHEtWoYOAMQjdjUN6QuBX2I9YI+EJFwq1WCQTLX2wRzKm6RAXwhTNS8rhsDdV14
# Ztk6MUSaM0C/CNdaSaTC5qmgZ92kJ7yhTzm1EVgX9yRcRo9k98FpiHaYdj1ZXUJ2
# h4mXaXpI8OCiEhtmmnTK3kse5w5jrubU75KSOp493ADkRSWJtppEGSt+wJS00mFt
# 6zPZxd9LBADMfRyVw4/3IbKyEbe7f/LVjHAsQWCqsWMYRJUadmJ+9oCw++hkpjPR
# iQfhvbfmQ6QYuKZ3AeEPlAwhHbJUKSWJbOUOUlFHdL4mrLZBdd56rF+NP8m800ER
# ElvlEFDrMcXKchYiCd98THU/Y+whX8QgUWtvsauGi0/C1kVfnSD8oR7FwI+isX4K
# Jpn15GkvmB0t9dmpsh3lGwIDAQABo4IBOjCCATYwDwYDVR0TAQH/BAUwAwEB/zAd
# BgNVHQ4EFgQU7NfjgtJxXWRM3y5nP+e6mK4cD08wHwYDVR0jBBgwFoAUReuir/SS
# y4IxLVGLp6chnfNtyA8wDgYDVR0PAQH/BAQDAgGGMHkGCCsGAQUFBwEBBG0wazAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAC
# hjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURS
# b290Q0EuY3J0MEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0
# LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwEQYDVR0gBAowCDAGBgRV
# HSAAMA0GCSqGSIb3DQEBDAUAA4IBAQBwoL9DXFXnOF+go3QbPbYW1/e/Vwe9mqyh
# hyzshV6pGrsi+IcaaVQi7aSId229GhT0E0p6Ly23OO/0/4C5+KH38nLeJLxSA8hO
# 0Cre+i1Wz/n096wwepqLsl7Uz9FDRJtDIeuWcqFItJnLnU+nBgMTdydE1Od/6Fmo
# 8L8vC6bp8jQ87PcDx4eo0kxAGTVGamlUsLihVo7spNU96LHc/RzY9HdaXFSMb++h
# UD38dglohJ9vytsgjTVgHAIDyyCwrFigDkBjxZgiwbJZ9VVrzyerbHbObyMt9H5x
# aiNrIv8SuFQtJ37YOtnwtoeW/VvRXKwYw02fc7cBqZ9Xql4o4rmUMIIGrjCCBJag
# AwIBAgIQBzY3tyRUfNhHrP0oZipeWzANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQG
# EwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNl
# cnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwHhcNMjIw
# MzIzMDAwMDAwWhcNMzcwMzIyMjM1OTU5WjBjMQswCQYDVQQGEwJVUzEXMBUGA1UE
# ChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQg
# UlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAxoY1BkmzwT1ySVFVxyUDxPKRN6mXUaHW0oPRnkyibaCw
# zIP5WvYRoUQVQl+kiPNo+n3znIkLf50fng8zH1ATCyZzlm34V6gCff1DtITaEfFz
# sbPuK4CEiiIY3+vaPcQXf6sZKz5C3GeO6lE98NZW1OcoLevTsbV15x8GZY2UKdPZ
# 7Gnf2ZCHRgB720RBidx8ald68Dd5n12sy+iEZLRS8nZH92GDGd1ftFQLIWhuNyG7
# QKxfst5Kfc71ORJn7w6lY2zkpsUdzTYNXNXmG6jBZHRAp8ByxbpOH7G1WE15/teP
# c5OsLDnipUjW8LAxE6lXKZYnLvWHpo9OdhVVJnCYJn+gGkcgQ+NDY4B7dW4nJZCY
# OjgRs/b2nuY7W+yB3iIU2YIqx5K/oN7jPqJz+ucfWmyU8lKVEStYdEAoq3NDzt9K
# oRxrOMUp88qqlnNCaJ+2RrOdOqPVA+C/8KI8ykLcGEh/FDTP0kyr75s9/g64ZCr6
# dSgkQe1CvwWcZklSUPRR8zZJTYsg0ixXNXkrqPNFYLwjjVj33GHek/45wPmyMKVM
# 1+mYSlg+0wOI/rOP015LdhJRk8mMDDtbiiKowSYI+RQQEgN9XyO7ZONj4KbhPvbC
# dLI/Hgl27KtdRnXiYKNYCQEoAA6EVO7O6V3IXjASvUaetdN2udIOa5kM0jO0zbEC
# AwEAAaOCAV0wggFZMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFLoW2W1N
# hS9zKXaaL3WMaiCPnshvMB8GA1UdIwQYMBaAFOzX44LScV1kTN8uZz/nupiuHA9P
# MA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDB3BggrBgEFBQcB
# AQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggr
# BgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1
# c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybDMuZGln
# aWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAI
# BgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQB9WY7Ak7Zv
# mKlEIgF+ZtbYIULhsBguEE0TzzBTzr8Y+8dQXeJLKftwig2qKWn8acHPHQfpPmDI
# 2AvlXFvXbYf6hCAlNDFnzbYSlm/EUExiHQwIgqgWvalWzxVzjQEiJc6VaT9Hd/ty
# dBTX/6tPiix6q4XNQ1/tYLaqT5Fmniye4Iqs5f2MvGQmh2ySvZ180HAKfO+ovHVP
# ulr3qRCyXen/KFSJ8NWKcXZl2szwcqMj+sAngkSumScbqyQeJsG33irr9p6xeZmB
# o1aGqwpFyd/EjaDnmPv7pp1yr8THwcFqcdnGE4AJxLafzYeHJLtPo0m5d2aR8XKc
# 6UsCUqc3fpNTrDsdCEkPlM05et3/JWOZJyw9P2un8WbDQc1PtkCbISFA0LcTJM3c
# HXg65J6t5TRxktcma+Q4c6umAU+9Pzt4rUyt+8SVe+0KXzM5h0F4ejjpnOHdI/0d
# KNPH+ejxmF/7K9h+8kaddSweJywm228Vex4Ziza4k9Tm8heZWcpw8De/mADfIBZP
# J/tgZxahZrrdVcA6KYawmKAr7ZVBtzrVFZgxtGIJDwq9gdkT/r+k0fNX2bwE+oLe
# Mt8EifAAzV3C+dAjfwAL5HYCJtnwZXZCpimHCUcr5n8apIUP/JiW9lVUKx+A+sDy
# Divl1vupL0QVSucTDh3bNzgaoSv27dZ8/DCCBrAwggSYoAMCAQICEAitQLJg0pxM
# n17Nqb2TrtkwDQYJKoZIhvcNAQEMBQAwYjELMAkGA1UEBhMCVVMxFTATBgNVBAoT
# DERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UE
# AxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MB4XDTIxMDQyOTAwMDAwMFoXDTM2
# MDQyODIzNTk1OVowaTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJ
# bmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IENvZGUgU2lnbmluZyBS
# U0E0MDk2IFNIQTM4NCAyMDIxIENBMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
# AgoCggIBANW0L0LQKK14t13VOVkbsYhC9TOM6z2Bl3DFu8SFJjCfpI5o2Fz16zQk
# B+FLT9N4Q/QX1x7a+dLVZxpSTw6hV/yImcGRzIEDPk1wJGSzjeIIfTR9TIBXEmtD
# mpnyxTsf8u/LR1oTpkyzASAl8xDTi7L7CPCK4J0JwGWn+piASTWHPVEZ6JAheEUu
# oZ8s4RjCGszF7pNJcEIyj/vG6hzzZWiRok1MghFIUmjeEL0UV13oGBNlxX+yT4Us
# SKRWhDXW+S6cqgAV0Tf+GgaUwnzI6hsy5srC9KejAw50pa85tqtgEuPo1rn3MeHc
# reQYoNjBI0dHs6EPbqOrbZgGgxu3amct0r1EGpIQgY+wOwnXx5syWsL/amBUi0nB
# k+3htFzgb+sm+YzVsvk4EObqzpH1vtP7b5NhNFy8k0UogzYqZihfsHPOiyYlBrKD
# 1Fz2FRlM7WLgXjPy6OjsCqewAyuRsjZ5vvetCB51pmXMu+NIUPN3kRr+21CiRshh
# WJj1fAIWPIMorTmG7NS3DVPQ+EfmdTCN7DCTdhSmW0tddGFNPxKRdt6/WMtyEClB
# 8NXFbSZ2aBFBE1ia3CYrAfSJTVnbeM+BSj5AR1/JgVBzhRAjIVlgimRUwcwhGug4
# GXxmHM14OEUwmU//Y09Mu6oNCFNBfFg9R7P6tuyMMgkCzGw8DFYRAgMBAAGjggFZ
# MIIBVTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBRoN+Drtjv4XxGG+/5h
# ewiIZfROQjAfBgNVHSMEGDAWgBTs1+OC0nFdZEzfLmc/57qYrhwPTzAOBgNVHQ8B
# Af8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwdwYIKwYBBQUHAQEEazBpMCQG
# CCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQQYIKwYBBQUHMAKG
# NWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290
# RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3JsMBwGA1UdIAQVMBMwBwYFZ4EMAQMw
# CAYGZ4EMAQQBMA0GCSqGSIb3DQEBDAUAA4ICAQA6I0Q9jQh27o+8OpnTVuACGqX4
# SDTzLLbmdGb3lHKxAMqvbDAnExKekESfS/2eo3wm1Te8Ol1IbZXVP0n0J7sWgUVQ
# /Zy9toXgdn43ccsi91qqkM/1k2rj6yDR1VB5iJqKisG2vaFIGH7c2IAaERkYzWGZ
# gVb2yeN258TkG19D+D6U/3Y5PZ7Umc9K3SjrXyahlVhI1Rr+1yc//ZDRdobdHLBg
# XPMNqO7giaG9OeE4Ttpuuzad++UhU1rDyulq8aI+20O4M8hPOBSSmfXdzlRt2V0C
# FB9AM3wD4pWywiF1c1LLRtjENByipUuNzW92NyyFPxrOJukYvpAHsEN/lYgggnDw
# zMrv/Sk1XB+JOFX3N4qLCaHLC+kxGv8uGVw5ceG+nKcKBtYmZ7eS5k5f3nqsSc8u
# pHSSrds8pJyGH+PBVhsrI/+PteqIe3Br5qC6/To/RabE6BaRUotBwEiES5ZNq0RA
# 443wFSjO7fEYVgcqLxDEDAhkPDOPriiMPMuPiAsNvzv0zh57ju+168u38HcT5uco
# P6wSrqUvImxB+YJcFWbMbA7KxYbD9iYzDAdLoNMHAmpqQDBISzSoUSC7rRuFCOJZ
# DW3KBVAr6kocnqX9oKcfBnTn8tZSkP2vhUgh+Vc7tJwD7YZF9LRhbr9o4iZghurI
# r6n+lB3nYxs6hlZ4TjCCBsAwggSooAMCAQICEAxNaXJLlPo8Kko9KQeAPVowDQYJ
# KoZIhvcNAQELBQAwYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJ
# bmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2
# IFRpbWVTdGFtcGluZyBDQTAeFw0yMjA5MjEwMDAwMDBaFw0zMzExMjEyMzU5NTla
# MEYxCzAJBgNVBAYTAlVTMREwDwYDVQQKEwhEaWdpQ2VydDEkMCIGA1UEAxMbRGln
# aUNlcnQgVGltZXN0YW1wIDIwMjIgLSAyMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAz+ylJjrGqfJru43BDZrboegUhXQzGias0BxVHh42bbySVQxh9J0J
# dz0Vlggva2Sk/QaDFteRkjgcMQKW+3KxlzpVrzPsYYrppijbkGNcvYlT4DotjIdC
# riak5Lt4eLl6FuFWxsC6ZFO7KhbnUEi7iGkMiMbxvuAvfTuxylONQIMe58tySSge
# TIAehVbnhe3yYbyqOgd99qtu5Wbd4lz1L+2N1E2VhGjjgMtqedHSEJFGKes+JvK0
# jM1MuWbIu6pQOA3ljJRdGVq/9XtAbm8WqJqclUeGhXk+DF5mjBoKJL6cqtKctvdP
# bnjEKD+jHA9QBje6CNk1prUe2nhYHTno+EyREJZ+TeHdwq2lfvgtGx/sK0YYoxn2
# Off1wU9xLokDEaJLu5i/+k/kezbvBkTkVf826uV8MefzwlLE5hZ7Wn6lJXPbwGqZ
# IS1j5Vn1TS+QHye30qsU5Thmh1EIa/tTQznQZPpWz+D0CuYUbWR4u5j9lMNzIfMv
# wi4g14Gs0/EH1OG92V1LbjGUKYvmQaRllMBY5eUuKZCmt2Fk+tkgbBhRYLqmgQ8J
# JVPxvzvpqwcOagc5YhnJ1oV/E9mNec9ixezhe7nMZxMHmsF47caIyLBuMnnHC1mD
# jcbu9Sx8e47LZInxscS451NeX1XSfRkpWQNO+l3qRXMchH7XzuLUOncCAwEAAaOC
# AYswggGHMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQM
# MAoGCCsGAQUFBwMIMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATAf
# BgNVHSMEGDAWgBS6FtltTYUvcyl2mi91jGogj57IbzAdBgNVHQ4EFgQUYore0GH8
# jzEU7ZcLzT0qlBTfUpwwWgYDVR0fBFMwUTBPoE2gS4ZJaHR0cDovL2NybDMuZGln
# aWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNIQTI1NlRpbWVTdGFt
# cGluZ0NBLmNybDCBkAYIKwYBBQUHAQEEgYMwgYAwJAYIKwYBBQUHMAGGGGh0dHA6
# Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBYBggrBgEFBQcwAoZMaHR0cDovL2NhY2VydHMu
# ZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNIQTI1NlRpbWVT
# dGFtcGluZ0NBLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAVaoqGvNG83hXNzD8deNP
# 1oUj8fz5lTmbJeb3coqYw3fUZPwV+zbCSVEseIhjVQlGOQD8adTKmyn7oz/AyQCb
# Ex2wmIncePLNfIXNU52vYuJhZqMUKkWHSphCK1D8G7WeCDAJ+uQt1wmJefkJ5ojO
# fRu4aqKbwVNgCeijuJ3XrR8cuOyYQfD2DoD75P/fnRCn6wC6X0qPGjpStOq/CUkV
# NTZZmg9U0rIbf35eCa12VIp0bcrSBWcrduv/mLImlTgZiEQU5QpZomvnIj5EIdI/
# HMCb7XxIstiSDJFPPGaUr10CU+ue4p7k0x+GAWScAMLpWnR1DT3heYi/HAGXyRkj
# gNc2Wl+WFrFjDMZGQDvOXTXUWT5Dmhiuw8nLw/ubE19qtcfg8wXDWd8nYiveQclT
# uf80EGf2JjKYe/5cQpSBlIKdrAqLxksVStOYkEVgM4DgI974A6T2RUflzrgDQkfo
# QTZxd639ouiXdE4u2h4djFrIHprVwvDGIqhPm73YHJpRxC+a9l+nJ5e6li6FV8Bg
# 53hWf2rvwpWaSxECyIKcyRoFfLpxtU56mWz06J7UWpjIn7+NuxhcQ/XQKujiYu54
# BNu90ftbCqhwfvCXhHjjCANdRyxjqCU4lwHSPzra5eX25pvcfizM/xdMTQCi2NYB
# DriL7ubgclWJLCcZYfZ3AYwwggdoMIIFUKADAgECAhAMMzQ0LuAfmONmPyLmRf1d
# MA0GCSqGSIb3DQEBCwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2Vy
# dCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25p
# bmcgUlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwHhcNMjIwNjI3MDAwMDAwWhcNMjMw
# ODA5MjM1OTU5WjBtMQswCQYDVQQGEwJBVTEYMBYGA1UECBMPTmV3IFNvdXRoIFdh
# bGVzMRIwEAYDVQQHEwlBZGFtc3Rvd24xFzAVBgNVBAoTDkdyZWlnIFNoZXJpZGFu
# MRcwFQYDVQQDEw5HcmVpZyBTaGVyaWRhbjCCAiIwDQYJKoZIhvcNAQEBBQADggIP
# ADCCAgoCggIBAOFVlQtjwzC7IMPzHlD6cagkjS1764l11Bb9cKAVq0UliI/cTgh2
# 02wsqHSmpPuamo5XeIB+G74CG9/oZFztMbm7HbE5UeuRkppwFCzAFilOX2gZWLPz
# ZLXMc4O80NOpQTbNQ7OgecpSaSHnKCv36CJdQ19jtmqHEqFLAT24raoT94JqQZ5b
# JG35zhSyfCyXZcGnejOfnF3zmtoTSZGDo5o1s29r4kIWk3vpZGK5hNnidHJSDULc
# WC7TVpRz1dL04Ce1KalnwSCW6FCJQ508vK3g4t6SEGBes7Ph35B8t4gvQ26oDlwV
# ugrUu+p4ynCP4OT5LY4gW627KbZgmtvgXUSfjNrgDAZN9VaMywaSM5JKxhKUfvNv
# Z1GF4yOgq3OKFCPczPcEkyxE/e5/X+Tks/75u75GRnsosYQV9NGxVLrEghs2Iwir
# 1e9DKMjRY0am0PAnbuvGvcKZ2jvMPUevNu5nV9tiPH+aDwQ34BAb5qC89NoYEpdH
# yNw37+SlTgKmEGNhows72QbjWL/cTFPo+uG+un2pjz6uMlSJLpb2TyQ796sFJP7+
# oZhYoXqgAYTtWrcYYut+kFPCuz7fUjIOBcdGa8eVvwh9np/dA/nFgR5f9T+cMj5x
# 6Y+GLQVDTwwbUTjddAb/aRvReTWSdcHytzkg7YSB0mD1OjK9J6JDilh5AgMBAAGj
# ggIGMIICAjAfBgNVHSMEGDAWgBRoN+Drtjv4XxGG+/5hewiIZfROQjAdBgNVHQ4E
# FgQUUV9/c4ckSxE0FGN1P7PQWXIrcnQwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQM
# MAoGCCsGAQUFBwMDMIG1BgNVHR8Ega0wgaowU6BRoE+GTWh0dHA6Ly9jcmwzLmRp
# Z2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNENvZGVTaWduaW5nUlNBNDA5NlNI
# QTM4NDIwMjFDQTEuY3JsMFOgUaBPhk1odHRwOi8vY3JsNC5kaWdpY2VydC5jb20v
# RGlnaUNlcnRUcnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZTSEEzODQyMDIxQ0Ex
# LmNybDA+BgNVHSAENzA1MDMGBmeBDAEEATApMCcGCCsGAQUFBwIBFhtodHRwOi8v
# d3d3LmRpZ2ljZXJ0LmNvbS9DUFMwgZQGCCsGAQUFBwEBBIGHMIGEMCQGCCsGAQUF
# BzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXAYIKwYBBQUHMAKGUGh0dHA6
# Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNENvZGVTaWdu
# aW5nUlNBNDA5NlNIQTM4NDIwMjFDQTEuY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZI
# hvcNAQELBQADggIBAF2/D+PsiX8TfULf7wjm8/oZ0BvJfJL4k7pCjjksvnuFkor+
# kpa+dXjpsSv1psIlo7aoiSYn+cPTF0g4Mc7R4P4ZDy4IKX/PvtBOs95ruE5cryeP
# K5CAl1T5nQbHDC9Ym0/73UUZRqxHdXe7c7OU0OUlMON0BmhXmwY608jmHZ63tYkK
# l/Orj6TC+FvJ+/WeT7zvjf71t/0frqZLEYGvBBdnCphHtxe0raLlV5l/caWXlXjQ
# 3FX4ZdyOMay/WTCiZ1z4/EnfxoI6Cd+wU/mcqjmcyPCCuVd2TeNJOE3BEQCUZyHa
# AFaE2m+sArx9nHy8Cc5CUTQH7Cf4tbJEI71qYIvYff6dLUhDqRvocpfSi5fq4col
# uXwIXbJ6cjAMFIySRGBg7rx2A3XVvSS4dAVKWFMnsoNF2l9wfyM63dPGImepTATn
# pDoqUQQqiCLFjuVztO+UJ1bOfhEHHZQGL+yZRBz61rpaTtz5xo5Tq72ev8HFWslR
# xVF8Y4GiwR0rVmv6lEWeASlMUdRHwCwyky9xnrf1OBIuMthnYi14QrKh1a3NdtSy
# NdhQsLpR1SRRT4DBGCZXJy7fY+sU7b7gkYSTHYyCf5KhRrqWaTOgz7ODwDA0SIIs
# dbY+AY8vbmTEuCbFALs9TOCrvMMriINikvokTZrRoiHwuDbnB3cIyCDGT6b1MYIG
# QjCCBj4CAQEwfTBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIElu
# Yy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgQ29kZSBTaWduaW5nIFJT
# QTQwOTYgU0hBMzg0IDIwMjEgQ0ExAhAMMzQ0LuAfmONmPyLmRf1dMAkGBSsOAwIa
# BQCgeDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgor
# BgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3
# DQEJBDEWBBSMj497fQzaxBsmeQ3w/dViR4NH1zANBgkqhkiG9w0BAQEFAASCAgDW
# EdI+7uy/PE0p5JVtmgsVKA5lK4XoR29pJBO87Az5X3wwEbdyPya5hobsp0h/iE0m
# 03vsYMV13xvGvMd+zuZMAwCz+QVyZ3lT5+Zj7bNv1ttNwnGNKzXwqGDHny9waY13
# Wo9ixfHx/QZ9Lkn5gXfoByR3O0jly5jc1tdbaeXeD8E8FEvzyZakR9BFBAzsiUmD
# KyzDqtCJXvok4iiFowBTE0qLPsqbqSztOVzglsrB6fAGrHMkDSQ5Cn1T/qAl3ays
# B/MaafTRQHxBq+0ARpxW/PfoKO7UI7C4gM5HO+4bniJAos6dOiqhdCmPwCAh2PDn
# f+Va2cKUojFcgv5hbvsSDQTnKf15m2iPV2F7IDEOOlqMZ/V7mEDA3S7CS4LpHblN
# 5VyTpOzzrgqZ4Fi3QjnwJZXoe2Rc3wOPN32qcrQs/FJC/8488oiXOXLMkQTAc724
# AJ4QA//2mj8bhlJjFgRnHBus7nj1r7BWVh4efmp5SbJSqDIYbjpxir8TrSesgRTz
# bbRTp54Ue6lmUNixHvki1wW5WvoKbaN1AhaP2NATKbKFo5jdl6NRj+A1XLOebYC+
# G4fpUlKnTfj8bZjveZ2sdzE338um/U5kOpe5PI4I5q9oIO/l3uSWtSUw7Yfa3mKi
# 2MQ4Zq+DJl3GI0YwJQX07TY3hBrLIojrJZsLEzr1paGCAyAwggMcBgkqhkiG9w0B
# CQYxggMNMIIDCQIBATB3MGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2Vy
# dCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNI
# QTI1NiBUaW1lU3RhbXBpbmcgQ0ECEAxNaXJLlPo8Kko9KQeAPVowDQYJYIZIAWUD
# BAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEP
# Fw0yMjExMTUwMDMzMjdaMC8GCSqGSIb3DQEJBDEiBCDeb40n9CLtgmyX2Fh1PbTq
# ThrASw/pjCD3RUuf8vcVOjANBgkqhkiG9w0BAQEFAASCAgC14sxDM2xjOtklBeki
# iU83MKpIUyHCfTscdNygFclXjBlkEPeL0GGtJOQmoKiQ6g5DAo33FZNRBPEg3f5Y
# D4cZ6PPIWYuDIpjM6xTd1SpujTCYeuh5GTcjzTSafGE9DjKQxsLT/S41L9+P4qYi
# 5zzFK8QV4+zF0r1HGQclCIxzGA0JzoSjLAyey8hon7ZZfHx1Nwf0MHSCxUMZaBuJ
# oJl0RGe5F1xUQ2yBX7izeHNaZgMq1aTNA+7wAsAI97bp2egMQ+VOpD0pAG+cNyFL
# evWDGWSZUtYoZEopTpbcosQFDp+qmSFoVlqe4pXzj2f0B0/yv7lurrMtXPh59aeu
# btVN3O/3KszYtucA2qg5AelHJlTAgFKbV7vXgavNuq2vnPbdOxXOa+n55SmrJGSW
# fkBaO2vmkLtxbTeq/i1maDhR++zeAzNc0YMR9xLGzgggyC3IQbIjf3V8z+jKza6c
# 8hUdzubHVdCF8ecEC5OPamf5DNZbwrAS5WBcXSfcNevdX4lxCioH/4iTJTYcZTMZ
# /R4IGI9kWfMVMzgrhWajA+tlMcbYqy0I+Jm2f5yJNvnLYkd1OiaU0Na12OcoboSr
# d4X1NYYtx47zMW7sAZsePB2rJl3Q3mLMsMhe9D0RmhetJ+t8+QwgY4JTUQQvCzBW
# 6XZoov0zFvzgfa2rSICX4dNpuQ==
# SIG # End signature block
