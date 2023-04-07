<#
.SYNOPSIS
	Removes group memberships from disabled AD user accounts. 

.DESCRIPTION
	This script removes group memberships from user accounts in the disabled Users OU and saves them to a per-user log file in a dated directory.
	
	This script depends on the ActiveDirectory module.
		#Install-WindowsFeature RSAT-AD-PowerShell
	
.PARAMETER OU
	Specifies the DistinguishedName of the AD OU to search. 
	If this is blank, a preconfigured OU can be specified as $DisabledOU .

.PARAMETER Undo
	Imports the CSV log files from today and adds users back to the groups they were removed from. 

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
	[switch] $Undo
)

#Requires -Modules activedirectory 
import-module activedirectory 

$datestring = ((get-date).tostring("yyyy-MM-dd"))
$LogFileDirectory = "c:\nexigen\offboarded\$datestring\"
$PrimaryGroup = get-adgroup "Domain Users" -properties @("primaryGroupToken")

If ($OU) {
	$DisabledOU = $OU
}
else {
	$DisabledOU = "OU=All Users,DC=autovalve,DC=com"
}



# create the log file directory if it doesn't exist
If (!(Test-Path -LiteralPath $LogFileDirectory)) { New-Item -Path $LogFileDirectory -ItemType Directory -ErrorAction Stop | Out-Null }

$exclusionarray = @("Guest", "Administrator", "krbtgt")
$DisabledADUsers = Get-ADUser -SearchBase $DisabledOU -filter 'enabled -eq "false"' | Where-Object { $exclusionarray -notcontains $_.sAMAccountName }

if (!($Undo)) {
	$ProgressCount = 0
	$ProgressActivity = "Removing group memberships from $($DisabledADUsers.count) users."
	foreach ($username in $DisabledADUsers) {
		$ProgressCount ++
		$ProgressMessage = "Now evaluating $($username.DistinguishedName)."
		Write-Progress -Activity $ProgressActivity -CurrentOperation $ProgressMessage -PercentComplete (($ProgressCount / $($DisabledADUsers.count)) * 100)
		
		$PreviousGroups = @()
		$PreviousGroupsLogFile = $LogFileDirectory + $($username.SamAccountName) + "-groups.csv";

		#set new Primary Group
		Set-ADUser -Identity $username -Replace @{primarygroupid = $PrimaryGroup.primaryGroupToken }

		# Get all group memberships
		$groups = get-adprincipalgroupmembership $username;

		# Loop through each group
		foreach ($group in $groups) {

			# Exclude Domain Users group
			if ($group.name -ne "domain users") {

				# Write progress to screen
				$ProgressMessage = "Attempting to remove the user $($username.DistinguishedName) from the group $($group.DistinguishedName)."
				Write-Verbose $ProgressMessage

				# Remove user from group
				try { remove-adgroupmember -Identity $($group.SamAccountName) -Member $($username.SamAccountName) -Confirm:$false }
				catch {
					$warning = "An error occurred while " + $ProgressMessage + " They may need to be corrected manually."
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
				#Add-AdGroupMember -Identity $($UndoGroup.DistinguishedName) -Members $($UndoGroup.User_DistinguishedName)
				[string] $Filter = $($UndoGroup.Group_Name)
				Get-ADGroup -Filter { Name -eq "$Filter" } | Add-AdGroupMember -Members $($UndoGroup.User_Name)
			}
			catch {
				$warning = "An error occurred while " + $ProgressMessage + " They may need to be corrected manually."
				Write-Warning $warning
			}
		}
	}
	Write-Progress -Activity $ProgressActivity -Completed
}