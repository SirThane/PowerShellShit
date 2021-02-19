
Function Set-CodeSigningCert
{
	Param (
		[Parameter(Mandatory = $false)]
		[System.String]$Thumbprint
	)
	
	$Certs = Get-ChildItem Cert:\CurrentUser\My\ -CodeSigningCert
	
	If ( $Certs.Length -eq 0 )
	{
		Write-Error "No code signing certificates are installed."
		Return
	}
	
	If ( -not $Thumbprint )
	{
		$Certs | Select-Object Issuer, Subject, Thumbprint, @{ n = "ValidPeriod"; e = { "$($_.NotBefore) - $($_.NotAfter)" } } | Format-List
		
		$Thumbprint = Read-Host "Enter the thumbprint for the certificate that will be used"
	}
	
	If ( $Certs.Thumbprint -notcontains $Thumbprint )
	{
		Write-Host "Installed code signing certificates:"
		$Certs | Select-Object Issuer, Subject, Thumbprint, @{ n = "ValidPeriod"; e = { "$($_.NotBefore) - $($_.NotAfter)" } } | Format-List
		Write-Error "Certificate `"$($Thumbprint)`" not installed."
		Return
	}
	
	If (-not (Test-Path HKCU:\CodeSigningCert))
	{
		New-Item HKCU:\CodeSigningCert
	}
	
	New-ItemProperty HKCU:\CodeSigningCert -Name Thumbprint -PropertyType String -Value $Thumbprint -Force
}


Function Sign-ScriptFile
{
	Param (
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({ Test-Path $_ })]
		[System.String]$File
	)
	
	If ( -not (Test-Path HKCU:\CodeSigningCert) )
	{
		New-Item HKCU:\CodeSigningCert
	}
	
	$Thumbprint = (Get-ItemProperty HKCU:\CodeSigningCert\ -Name Thumbprint).Thumbprint
	
	$Certs = Get-ChildItem Cert:\CurrentUser\My\ -CodeSigningCert
	
	If ( -not $Thumbprint )
	{
		Write-Error "Certificate not set. Use Set-CodeSigningCert."
		Return
	}
	
	If ( $Certs.Thumbprint -notcontains $Thumbprint )
	{
		Write-Error "Invalid certificate `"$($Thumbprint)`" selected. Use Set-CodeSigningCert"
		Return
	}
	
	Set-AuthenticodeSignature $File -Certificate ($Certs | Where-Object { $_.Thumbprint -eq $Thumbprint })
}
