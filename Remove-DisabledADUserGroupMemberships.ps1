<#
.SYNOPSIS
	Removes group memberships from disabled AD user accounts. 

.DESCRIPTION
	This script removes group memberships from user accounts in the disabled Users OU and saves them to a per-user log file in a dated directory.
	
	This script depends on the ActiveDirectory module.
		#Install-WindowsFeature RSAT-AD-PowerShell
	
.PARAMETER OU
	Specifies the DistinguishedName of the AD OU to search. 
	If this is not specified, the script will search all OUs under the domain root.

.PARAMETER Undo
	Imports the CSV log files from today and adds users back to the groups they were removed from. 

.PARAMETER SkipUpdateCheck
	This script checks whether it matches the current published version on GitHub. 
	If it does not match, it will prompt whether to run the current version. 
	If you customize the $SearchOU parameter, set this $true. 

.EXAMPLE
	.\Remove-DisabledADUserGroupMemberships.ps1 -OU "OU=Terminated Users,DC=example,DC=org"

.LINK
	https://github.com/saeraphas/Remove-DisabledADUserGroupMemberships.ps1

.NOTES
    Author:             Douglas Hammond 
	License: 			This script is distributed under "THE BEER-WARE LICENSE" (Revision 42):
						As long as you retain this notice you can do whatever you want with this stuff.
						If we meet some day, and you think this stuff is worth it, you can buy me a beer in return.

#>
Param (
	[Parameter(ValueFromPipelineByPropertyName)]
	[string] $OU,
	[switch] $Undo,
	[switch] $SkipUpdateCheck
)

#Requires -Modules activedirectory 

function CheckForUpdates($GitHubURI) {
    IF ($($myInvocation.ScriptName).Length -eq 0) { Write-Verbose "No local script path exists, skipping cloud version comparison." } else {
        $LocalScriptPath = $myInvocation.ScriptName
        $LocalScriptContent = Get-Content $LocalScriptPath
        $CloudScriptPath = $GitHubURI
        $CloudScriptContent = (Invoke-WebRequest -UseBasicParsing $CloudScriptPath).Content

        $localstringAsStream = [System.IO.MemoryStream]::new()
        $writer = [System.IO.StreamWriter]::new($localstringAsStream)
        $writer.write($LocalScriptContent)
        $writer.Flush()
        $localstringAsStream.Position = 0
        $LocalScriptHash = (Get-FileHash -InputStream $localstringAsStream -Algorithm SHA256).Hash

        $cloudstringAsStream = [System.IO.MemoryStream]::new()
        $writer = [System.IO.StreamWriter]::new($cloudstringAsStream)
        $writer.write($CloudScriptContent)
        $writer.Flush()
        $cloudstringAsStream.Position = 0
        $CloudScriptHash = (Get-FileHash -InputStream $cloudstringAsStream -Algorithm SHA256).Hash

        Write-Verbose "Local Script Path: $LocalScriptPath"
        Write-Verbose "Local Script Hash: $LocalScriptHash"
        Write-Verbose "Cloud Script Hash: $CloudScriptHash"

        If ($LocalScriptHash -ne $CloudScriptHash) {
            $MismatchWarning = "The running script does not match the current version on GitHub."
            Write-Warning $MismatchWarning
            $MismatchPrompt = 'Enter "y" to switch to the GitHub version now, or any other key to continue using the local version.'
            $Answer = Read-Host $MismatchPrompt
            If ($Answer -eq "y") {
                Write-Verbose "Switching to GitHub version."
                Invoke-Expression $CloudScriptContent; exit
            }
        }
    }
}

If ($OU) { $SearchOU = $OU } else {
	$SearchOU = $($(Get-ADRootDSE).DefaultNamingContext) #if you customize this, uncomment the update check
	#$SkipUpdateCheck = $true
}

#Check GitHub for a modified version
If (!($SkipUpdateCheck)) { CheckForUpdates("https://raw.githubusercontent.com/saeraphas/Remove-DisabledADUserGroupMemberships.ps1/main/Remove-DisabledADUserGroupMemberships.ps1") }

import-module activedirectory 
$datestring = ((get-date).tostring("yyyy-MM-dd"))
$LogFileDirectory = "c:\nexigen\offboarded\$datestring\"
$DomainUsersGroupToken = (get-adgroup "Domain Users" -properties @("primaryGroupToken")).primaryGroupToken
$DomainGuestsGroupToken = (get-adgroup "Domain Guests" -properties @("primaryGroupToken")).primaryGroupToken

# create the log file directory if it doesn't exist
If (!(Test-Path -LiteralPath $LogFileDirectory)) { New-Item -Path $LogFileDirectory -ItemType Directory -ErrorAction Stop | Out-Null }

$ExcludedUsers = @("Guest", "Administrator", "krbtgt")
$DisabledADUsers = Get-ADUser -SearchBase $SearchOU -filter 'enabled -eq "false"' -Properties PrimaryGroupID | Where-Object { $ExcludedUsers -notcontains $_.sAMAccountName }

if (!($Undo)) {
	$ProgressCount = 0
	$ProgressActivity = "Removing group memberships from $($DisabledADUsers.count) users."
	foreach ($username in $DisabledADUsers) {
		$ProgressCount ++
		$ProgressMessage = "Now evaluating $($username.DistinguishedName)."
		Write-Progress -Activity $ProgressActivity -CurrentOperation $ProgressMessage -PercentComplete (($ProgressCount / $($DisabledADUsers.count)) * 100)
		
		$PreviousGroups = @()
		$PreviousGroupsLogFile = $LogFileDirectory + $($username.SamAccountName) + "-groups.csv";

		#Set account Primary Group to Domain Users, unless account is in Domain Guests
		#		$PrimaryGroup = (Get-ADUser $username -Properties PrimaryGroupID).primaryGroupID	#superfluous query?
		$PrimaryGroup = $($username.primaryGroupID)
		Write-Verbose "Account Primary Group is $PrimaryGroup, Domain Users is $DomainUsersGroupToken, Domain Guests is $DomainGuestsGroupToken."
		if (($PrimaryGroup -ne $DomainUsersGroupToken) -and ($PrimaryGroup -ne $DomainGuestsGroupToken)) {
			Get-ADGroup -Filter { Name -eq "Domain Users" } | Add-AdGroupMember -Members $username
			Set-ADUser -Identity $username -Replace @{primarygroupid = $DomainUsersGroupToken }
		}

		# Get all group memberships
		$groups = get-adprincipalgroupmembership $username;

		# Loop through each group
		foreach ($group in $groups) {

			# Don't try to remove the account from Domain Users and Domain Guests
			$ExcludedGroups = @("Domain Users", "Domain Guests")
			if ($ExcludedGroups -notcontains $group.name) {

				# Write progress to screen
				$ProgressMessage = "Attempting to remove the user $($username.DistinguishedName) from the group $($group.DistinguishedName)."
				Write-Verbose $ProgressMessage

				# Remove user from group
				try { remove-adgroupmember -Identity $($group.SamAccountName) -Member $($username.SamAccountName) -Confirm:$false }
				catch {
					$warning = "An error occurred while " + $ProgressMessage + " This may need to be corrected manually."
					Write-Warning $warning
				}

				# Add group names to per-user object for CSV export
				$PreviousGroupHash = $null
				$PreviousGroupHash = @{
					'User_Name'  = "$($username.sAMAccountName)"
					'Group_Name' = $($group.Name)
					#'User_DistinguishedName'  = $($username.DistinguishedName)
					#'Group_DistinguishedName' = $($group.DistinguishedName) 
				}
				$PreviousGroupObject = $null
				$PreviousGroupObject = New-Object -TypeName PSObject -Property $PreviousGroupHash
				$PreviousGroups += $PreviousGroupObject
			}

		}
		# Export CSV of removed groups
		if ($($PreviousGroups.count) -gt 0) {
			$PreviousGroups | Sort-Object -Property DistinguishedName | Export-Csv -NoTypeInformation -Path $PreviousGroupsLogFile
		}
		else {
			Write-Verbose "No groups removed for $($username.DistinguishedName)."
		}
	
	}
	Write-Progress -Activity $ProgressActivity -Completed
}
else {
	$ProgressCount = 0
	$UndoLogFiles = Get-ChildItem -Path $LogFileDirectory
	$ProgressActivity = "Removing group memberships from $($UndoLogFiles.count) user log files."
	foreach ($LogFile in $UndoLogFiles) {
		$ProgressMessage = "Importing $($LogFile.FullName)."
		$ProgressCount ++
		Write-Progress -Activity $ProgressActivity -CurrentOperation $ProgressMessage -PercentComplete (($ProgressCount / $($UndoLogFiles.count)) * 100)
		$UndoGroups = Import-Csv -Path $($LogFile.FullName)
		ForEach ($UndoGroup in $UndoGroups) {
			$ProgressMessage = "Attempting to add the user $($UndoGroup.User_Name) to the group $($UndoGroup.Group_Name)."
			Write-Verbose $ProgressMessage
			try {
				[string] $Filter = $($UndoGroup.Group_Name)
				Get-ADGroup -Filter { Name -eq $Filter } | Add-AdGroupMember -Members $($UndoGroup.User_Name)
			}
			catch {
				$warning = "An error occurred while " + $ProgressMessage + " This may need to be corrected manually."
				Write-Warning $warning
			}
		}
	}
	Write-Progress -Activity $ProgressActivity -Completed
}