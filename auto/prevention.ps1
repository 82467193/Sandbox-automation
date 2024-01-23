#block the execution from anyone 
#After the block, check the file permission and start the python script
#Write a script to check system registry

$file_path = Read-Host "Enter the file path"
$len = $file_path.Length
$sub = $file_path.SubString(1,$len-2)

if(Test-Path $sub){
	Write-Host "File-exists."
	icacls $file_path /deny "Everyone:(X)"

	$acl = Get-Acl $sub
	foreach ($access in $acl.Access) {
		Write-Host ("{0} {1} {2}" -f $access.IdentityReference, $access.FileSystemRights, $access.AccessControlType)

		if($access.IdentityReference -eq "Everyone" -and $access.FileSystemRights -eq "ExecuteFile" -and $access.AccessControlType -eq "Deny"){
			Write-Host "File does not have execution permissions."
			break
		}else{
			Write-Host "File has execution permissions."
			#Delete the file and terminate the process
			Remove-Item -Path $sub
			Write-Host "Stopping the process....."
			exit
		}
	}	
	<# foreach($access in $acl.Access){
		if($access.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::ExecuteFile){
			Write-Host "File has execution permissions."
		}else{
			Write-Host "File does not have execution permissions."
		}
	} #>
	
	Write-Host "Executing python script....."
	python "C:\Users\alex\Desktop\auto\auto.py" $file_path
	
	
}else{
	Write-Host "File does not exist."
}