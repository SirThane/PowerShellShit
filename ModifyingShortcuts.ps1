
Function Set-Shortcut
{
	Param (
		[Parameter(Mandatory = $true, Position = 0)]
		[ValidateNotNull()]
		[System.String]$Name,
		
		[Parameter(Mandatory = $false, Position = 1)]
		[ValidateNotNull()]
		[System.String]$TargetPath,
		
		[Parameter(Mandatory = $false)]
		[System.String]$Arguments = $null,
		
		[Parameter(Mandatory = $false)]
		[System.String]$WorkingDirectory = $null,
		
		[Parameter(Mandatory = $false)]
		[ValidateSet("Normal", "Maximized", "Minimized")]
		[System.String]$WindowStyle = $null,
		
		[Parameter(Mandatory = $false)]
		[System.String]$IconLocation = $null,
		
		[Parameter(Mandatory = $false)]
		[System.String]$Description = $null
	)
	
  # File name without relative or absolute path
	If ( -not (Split-Path $Name) )
	{
		$Name = Join-Path (Get-Location) $Name
	}
  
  # Wscript.Shell doesn't share pwd with Powershell, so resolve `.\` to absolute path if it was used
	Else
	{
		$Name = Join-Path (Resolve-Path (Split-Path $Name)) $Name
	}
	
  # If .lnk exists, it will grab current properties
	$WscShell = New-Object -comObject WScript.Shell
	$Shortcut = $WscShell.CreateShortcut($Name)
	
	$WindowStyles = @{
		Normal = 1
		Maximized = 3
		Minimized = 7
	}
	
	$Attributes = @{
		TargetPath       = $TargetPath
		Arguments  		 = $Arguments
		WorkingDirectory = $WorkingDirectory
		WindowStyle	     = $WindowStyles.$WindowStyle
		IconLocation	 = $IconLocation
		Description	     = $Description
	}
	
  # Only update properties that were specified in cmdlet arguments
	ForEach ( $Attribute in $Attributes.Keys ) {
		If ( $Attributes.$Attribute )
		{
			$Shortcut.$Attribute = $Attributes.$Attribute
		}
	}
	
	$Shortcut.Save()
}
