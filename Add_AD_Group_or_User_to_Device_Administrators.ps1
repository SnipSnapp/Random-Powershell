<#
Harrison Koll 4/24/2023
.Synopsis
Inputfile is the name of the file or list of devices.
grp_or_usr is the name of the group or user that you want to add to  to add to the local Administrators group.
This script is useful when net localgroup or Add-localgroupmember are not available. IE. On legacy devices, it works 100% on the time, tested from Windows 2k on up.
#>
param(
    [Parameter(ParameterSetName='Input')]
    [string]
        $InputFile,
    [string]
        $grp_or_usr
)



function Resolve-SamAccount {
param(
    [string]
        $SamAccount,
    [boolean]
        $Exit
)
    process {
        try
        {
            $ADResolve = ([adsisearcher]"(samaccountname=$grp_or_usr)").findone().properties['samaccountname']
        }
        catch
        {
            $ADResolve = $null
        }

        if (!$ADResolve) {
            Write-Warning "User `'$SamAccount`' not found in AD, please input correct SAM Account Name."
            if ($Exit) {
                exit
            }
        }
        $ADResolve
    }
}

if (!$grp_or_usr) {
    $grp_or_usr = Read-Host "Please input the Group or User you wish to add to the target machine(s) local Administrators group."
}

if ($grp_or_usr -notmatch '\\') {
    $ADResolved = (Resolve-SamAccount -SamAccount $grp_or_usr -Exit:$true)
    $grp_or_usr = 'WinNT://',"$env:userdomain",'/',$ADResolved -join ''
} else {
    $ADResolved = ($grp_or_usr -split '\\')[1]
    $DomainResolved = ($grp_or_usr -split '\\')[0]
    $grp_or_usr = 'WinNT://',$DomainResolved,'/',$ADResolved -join ''
}


if (!$InputFile) {
		$Computer = Read-Host "Please input computer or file name."
}
else{
    if(!(Test-Path -Path $InputFile)){
    	[string[]]$Computers = $InputFile.Split(',')
    }
    else{
        $Computers = get-content $InputFile
    }

	$Computers | ForEach-Object {
		$_
        $ledevice = $_
		Write-Host "Adding `'$ADResolved`' to Administrators group on `'$_`'."
        $curr_time = Get-Date
		try {
			([ADSI]"WinNT://$_/Administrators,group").add($grp_or_usr)
			Write-Host -ForegroundColor Green "Successfully Added `'$ADResolved`' to `'$_`'."
            "'$curr_time'`t'$_'`t'$ledevice'" >> Successfuladditions.log
            
		} catch {
			Write-Warning "$_"
            "'$curr_time'`t'$_'`t'$ledevice'" >> Failedadditions.log
		}	
	}
}
