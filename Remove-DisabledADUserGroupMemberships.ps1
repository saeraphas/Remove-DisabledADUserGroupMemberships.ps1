<#
.SYNOPSIS
	Removes group memberships from disabled AD user accounts. 
.DESCRIPTION
	This script removes group memberships from user accounts in the disabled Users OU and saves them to a per-user log file. 	
	
	This script depends on the ActiveDirectory module.
		#Install-WindowsFeature RSAT-AD-PowerShell
	This script depends on ImportExcel module.
		#https://github.com/dfinke/ImportExcel
		#Install-Module -Name ImportExcel	
	
.PARAMETER OU
	Specifies the DistinguishedName of the AD OU to search. 
	If this is blank, a preconfigured OU can be specified as $DisabledOU .

.EXAMPLE
	.\Remove-DisabledADUserGroupMemberships.ps1 -OU "OU=Terminated Users,DC=example,DC=org"

.NOTES
    Author:             Douglas Hammond 
	License: 			This script is distributed under "THE BEER-WARE LICENSE" (Revision 42):
						As long as you retain this notice you can do whatever you want with this stuff.
						If we meet some day, and you think this stuff is worth it, you can buy me a beer in return.

#>
Param (
	[Parameter(ValueFromPipelineByPropertyName)]
	[string] $OU
)

#Requires -Modules activedirectory 
import-module activedirectory 

$datestring = ((get-date).tostring("yyyy-MM-dd"))
$LogFileDir = "c:\nexigen\offboarded\$datestring"
$PrimaryGroup = get-adgroup "Domain Users" -properties @("primaryGroupToken")

If (!($null -eq $OU)) {
	$DisabledOU = $OU
}
else {
	$DisabledOU = "OU=All Users,DC=autovalve,DC=com"
}

# create the log file directory if it doesn't exist
If (!(Test-Path -LiteralPath $LogFileDir)) { New-Item -Path $LogFileDir -ItemType Directory -ErrorAction Stop | Out-Null }

foreach ($username in (Get-ADUser -SearchBase $DisabledOU -filter 'enabled -eq "false"')) {

	$PreviousGroups = @()

	#set new Primary Group
	Set-ADUser -Identity $username -Replace @{primarygroupid = $PrimaryGroup.primaryGroupToken }

	# Get all group memberships
	$groups = get-adprincipalgroupmembership $username;

	# Loop through each group
	foreach ($group in $groups) {

		# Exclude Domain Users group
		if ($group.name -ne "domain users") {

			# Write progress to screen
			Write-Verbose "Attempting to remove the user $username from the group $group."

			# Add group names to per-user log file
			$grouplogtxt = $LogFileDir + $username.SamAccountName + "-groups.txt";
			$group.name >> $grouplogtxt

			# Remove user from group
			try { remove-adgroupmember -Identity $group.SamAccountName -Member $username.SamAccountName -Confirm:$false }
			catch {
				$message = "An error occurred while removing the user $username from the group $group. They may need to be removed manually."
				Write-Warning $message
#				$message >> $grouplogtxt
			}

			# Add group names to per-user object for CSV export
			$PreviousGroupLogFile = $LogFileDir + $username.SamAccountName + "-groups.csv";
			$PreviousGroupProperties = @{Name = $($group.name) }
			$PreviousGroupObject = New-Object -TypeName PSObject -Property $PreviousGroupProperties
			$PreviousGroups += $PreviousGroupObject

		}

	}
	# Export CSV of removed groups
	$PreviousGroups | Export-Csv -NoTypeInformation -Path $PreviousGroupLogFile

}