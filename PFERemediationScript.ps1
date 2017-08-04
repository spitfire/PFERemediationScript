
# ==================================================================
# This Sample Code is provided for the purpose of illustration only 
# and is not intended to be used in a production environment.  
# THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT 
# WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED 
# TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR 
# PURPOSE.  We grant You a nonexclusive, royalty-free right to use and modify 
# the Sample Code and to reproduce and distribute the object code form of the 
# Sample Code, provided that You agree: (i) to not use Our name, logo, or 
# trademarks to market Your software product in which the Sample Code is 
# embedded; (ii) to include a valid copyright notice on Your software product 
# in which the Sample Code is embedded; and (iii) to indemnify, hold harmless, 
# and defend Us and Our suppliers from and against any claims or lawsuits, 
# including attorneys’ fees, that arise or result from the use or 
# distribution of the Sample Code.
#
# ================================================================== 

#Current Version information for script
[string]$strScriptVersion = "16.03.5"

#region #################################### START FUNCTIONS ####################################>

Function Write-CHLog (){
    <#
    .SYNOPSIS
    Log output and function called
    .DESCRIPTION
    Accepts string values for the function called and for the actual message to be logged and writes it to the main PFE Script logfile
    .EXAMPLE
    Write-CHLog -function "RegWrite" -message "Setting XXXX in the registry"
    .EXAMPLE
    Write-CHLog "RegWrite" "Setting XXXX in the registry"
    .PARAMETER Function
    The function that called for Write-CHLog
    .PARAMETER Message
    The content of the message to be logged
    #>

    param
    (
        [Parameter(Mandatory=$True,
        ValueFromPipelineByPropertyName=$True)]
        [string]$strFunction,

        [Parameter(Mandatory=$True,
        ValueFromPipelineByPropertyName=$True)]
        [string]$strMessage
    )
    
    <#
    $strFunction = "Main"
    $strMessage = "Test Write-CHLog"
    #>

    #set log file location
    [string]$strLogFile = "$global:strCurrentLocation\PS-PFERemediationScript.log"

    #define output to log file    
    [string]$strOutput = (Get-Date -Format "yyyy-MM-dd HH:mm:ss:ff") + " - " + $strFunction + "(): " + $strMessage

    #append the output to the file; this will create the file if necessary as well
        
    Try{
        $strOutput | Out-File -FilePath $strLogFile -Append
    }
    Catch{
        "Cannot write to log file; exiting script"
        Exit(1)
    }
}

Function Get-CHRegistryValue (){
    <#
    .SYNOPSIS
    Read Registry Value

    .DESCRIPTION
    Accepts string values for registry key and registry value requested

    .EXAMPLE
    Get-CHRegistryValue -strRegKey $strPFEKeyPath -strRegValue "ScriptLog"

    .EXAMPLE
    Get-CHRegistryValue "HKLM:\SOFTWARE\Microsoft\CCM\Logging\@Global" "LogDirectory"

    .PARAMETER strRegKey
    The path to the registry key being requested

    .PARAMETER strRegValue
    The name of the registry value requested
    #>
    
    param
    (
        [Parameter(Mandatory=$True,
        ValueFromPipelineByPropertyName=$True)]
        [string]$strRegKey,

        [Parameter(Mandatory=$True,
        ValueFromPipelineByPropertyName=$True)]
        [string]$strRegValue
    )
    
    if($global:blnDebug ){ Write-CHLog "Get-CHRegistryValue" "Getting registry value for $strRegKey\$strRegValue" }
    
    Try{
        $strRegRead = Get-Item $strRegKey -ErrorAction Stop | ForEach { $_.GetValue($strRegValue) }
        if ($strRegRead -eq $null){
            $strRegRead = ""
            If($global:blnDebug ){ Write-CHLog "Get-CHRegistryValue" "Warning: The value for $strRegKey\$strRegValue is empty" }
        }
    }
    Catch{
        $strRegRead = "Error"
        $strErrorMsg = ($Error[0].toString()).Split(".")[0]
        
        Write-CHLog "Get-CHRegistryValue" "Failed to get $strRegValue as the path $strRegKey does not exist"
        Write-CHLog "Get-CHRegistryValue" "Return error: $strErrorMsg"
    }

    #returning status
    if($global:blnDebug ){Write-CHLog "Get-CHRegistryValue" "Return value is $strRegRead"}
    return $strRegRead
}

Function Set-CHRegistryValue (){
    <#
    .SYNOPSIS
    Write Registry Value

    .DESCRIPTION
    Accepts string values for registry key and registry value to include data and data type to write

    .EXAMPLE
    Set-CHRegistryValue -strRegKey "HKLM:\SOFTWARE\Microsoft\Microsoft PFE Remediation for Configuration Manager" -strRegValue "Test Set Reg Value" -strData "Worked again"

    .EXAMPLE
    Set-CHRegistryValue "HKLM:\SOFTWARE\Microsoft\Microsoft PFE Remediation for Configuration Manage" -strRegValue "Test New Reg Value" -strData "Worked" -strDataType "string"

    .PARAMETER strRegKey
    The path to the registry key being requested

    .PARAMETER strRegValue
    The name of the registry value requested

    .PARAMETER strData
    The path to the registry key being requested

    .PARAMETER strDataType
    The data type for a new registry entry; this is only required if blnNew is True; setting to not mandatory since creating new registry entries is rare

    .PARAMETER blnNew
    To force the type of a new registry entry, the type is required; if blnNew is True, strDataType will be used to force this type
    #>
    
    param
    (
        [Parameter(Mandatory=$True,
        ValueFromPipelineByPropertyName=$True)]
        [string]$strRegKey,

        [Parameter(Mandatory=$True,
        ValueFromPipelineByPropertyName=$True)]
        [string]$strRegValue,

        [Parameter(Mandatory=$True,
        ValueFromPipelineByPropertyName=$True)]
        [string]$strData,

        [Parameter(Mandatory=$False,
        ValueFromPipelineByPropertyName=$True)]
        [ValidateSet('dword','string','qword','expandstring','binary','multistring')]
        [string]$strDataType
    )
    
    if($strDataType -ne "multistring"){
        [string]$strRegKeyExists = Get-CHRegistryValue -strRegKey $strRegKey -strRegValue $strRegValue

        #for cases where new registry values are written, new-itemproperty will set the type
        if ($strRegKeyExists -eq "Error"){
            #logging
            if($global:blnDebug ){ Write-CHLog "Set-CHRegistryValue" "Setting new registry value for $strRegKey\$strRegValue to $strData" }
        
            Try{
                New-ItemProperty $strRegKey -Name $strRegValue -Value $strData -PropertyType $strDataType -ErrorAction Stop | Out-Null
                if($global:blnDebug ){ Write-CHLog "Set-CHRegistryValue" "New registry value $strRegKey\$strRegValue was created; the value was set to $strData" }
            }
            Catch{
                $strErrorMsg = ($Error[0].toString()).Split(".")[0]
                Write-CHLog "Set-CHRegistryValue" "New registry value $strRegKey\$strRegValue was not created; the error is $strErrorMsg"
            }
        }
        else{
            #logging
            if($global:blnDebug ){ Write-CHLog "Set-CHRegistryValue" "Setting registry value for $strRegKey\$strRegValue to $strData" }

            #most cases are updating existing registry entries
            Try{
                Set-ItemProperty $strRegKey -Name $strRegValue -Value $strData -ErrorAction Stop
                if($global:blnDebug ){ Write-CHLog "Set-CHRegistryValue" "Registry value $strRegKey\$strRegValue was set to $strData" }
            }
            Catch{
                $strErrorMsg = ($Error[0].toString()).Split(".")[0]
                Write-CHLog "Set-CHRegistryValue" "New registry value $strRegKey\$strRegValue was not created; the error is $strErrorMsg"
            }
        }
    }
    else{
        [array]$arrRegKeyExists = Get-CHRegistryValue -strRegKey $strRegKey -strRegValue $strRegValue

        if($global:blnDebug ){ Write-CHLog "Set-CHRegistryValue" "Registry data type is multistring" }

        #for cases where new registry values are written, new-itemproperty will set the type
        if ($arrRegKeyExists[0] -eq "Error"){
            #logging
            if($global:blnDebug ){ Write-CHLog "Set-CHRegistryValue" "Setting new registry value for $strRegKey\$strRegValue to $strData" }

            #convert strData to array
            [array]$arrData = $strData.Split(",")
        
            Try{
                New-ItemProperty $strRegKey -Name $strRegValue -Value $arrData -PropertyType $strDataType -ErrorAction Stop | Out-Null
                if($global:blnDebug ){ Write-CHLog "Set-CHRegistryValue" "New registry value $strRegKey\$strRegValue was created; the value was set to $strData" }
            }
            Catch{
                $strErrorMsg = ($Error[0].toString()).Split(".")[0]
                Write-CHLog "Set-CHRegistryValue" "New registry value $strRegKey\$strRegValue was not created; the error is $strErrorMsg"
            }
        }
        else{
            #logging
            if($global:blnDebug ){ Write-CHLog "Set-CHRegistryValue" "Setting registry value for $strRegKey\$strRegValue to $strData" }

            #convert strData to array
            [array]$arrData = $strData.Split(",")

            #most cases are updating existing registry entries
            Try{
                Set-ItemProperty $strRegKey -Name $strRegValue -Value $arrData -ErrorAction Stop
                if($global:blnDebug ){ Write-CHLog "Set-CHRegistryValue" "Registry value $strRegKey\$strRegValue was set to $strData" }
            }
            Catch{
                $strErrorMsg = ($Error[0].toString()).Split(".")[0]
                Write-CHLog "Set-CHRegistryValue" "New registry value $strRegKey\$strRegValue was not created; the error is $strErrorMsg"
            }
        }
    }
}

Function Test-CHWriteWMI (){
    <#
    .SYNOPSIS
    Checks the ability to write to WMI
    .DESCRIPTION
    Attempts to write test objects to WMI namespace and returns boolean value
    .EXAMPLE
    Test-CHWriteWMI -strNamespace "root"
    .EXAMPLE
    Test-CHWriteWMI "root\ccm"
    .PARAMETER strNamespace
    String value for the namespace requested for reading
    #>
    param
    (
        [Parameter(Mandatory=$True,
        ValueFromPipelineByPropertyName=$True)]
        [string]$strNamespace
    )
 
    <#Test settings to run without function call
	$strNamespace = "root\ccm"
	#>
    If($global:blnDebug ){ Write-CHLog "Test-CHWriteWMI" "Attempting to write to $strNamespace" }

    #check for prior existence of PFE class in $strNamespace
    if ((Get-WmiObject -namespace $strNamespace -Class "PFE" -ErrorAction SilentlyContinue) -ne $null){
        If($global:blnDebug ){ Write-CHLog "Test-CHWriteWMI" "The test class PFE already existed in Namespace $strNamespace; cleaning up created class" }
        Try{
            #Delete test class from namespace prior to testing
            If($global:blnDebug ){ Write-CHLog "Test-CHWriteWMI" "Namespace $strNamespace can be written to; cleaning up created class" }
            [wmiclass]$objOldClass = Get-WmiObject -namespace $strNamespace -Class "PFE"
            $objOldClass.Delete()
        }
        Catch{
            Write-CHLog "Test-CHWriteWMI" "Failed to delete test class PFE from $strNamespace"
            return $False
        }
    }
            
    Try{
        #attempt creation of new class object in namespace
        [wmiclass]$objWMIClass = New-Object System.Management.ManagementClass($strNamespace,$null,$null)
        $objWMIClass.Name = "PFE"
        $objWMIClass.Put() | Out-Null

        Try{
            #add a property to the class called TestProperty and give it a value of TestValue
            $objWMIClass.Properties.Add("TestProperty","")
            $objWMIClass.SetPropertyValue("TestProperty","TestValue")
            $objWMIClass.Put() | Out-Null

            Try{
                #create a new instance of the PFE class and changing the value of the TestProperty in this instance
                $objNewWMIInstance = $objWMIClass.CreateInstance()
                $objNewWMIInstance.TestProperty = "New Instance"

                Try{
                    #Cleanup test class in the namespace and returning True for success
                    If($global:blnDebug ){ Write-CHLog "Test-CHWriteWMI" "Namespace $strNamespace can be written to; cleaning up created class" }
                    $objWMIClass.Delete()
                    return $True
                }
                Catch{
                    Write-CHLog "Test-CHWriteWMI" "Failed to delete test class PFE from $strNamespace"
                    return false
                }
            }
            Catch{
                Write-CHLog "Test-CHWriteWMI" "Failed to create instance of class PFE to $strNamespace"
                return $false
            }
        }
        Catch{
            Write-CHLog "Test-CHWriteWMI" "Failed to write property TestProperty to PFE class of namespace $strNamespace"
            return $false
        }
    }
    Catch{
        Write-CHLog "Test-CHWriteWMI" "Failed to write class PFE to $strNamespace"
        return $false
    }
}

Function Test-CHWMIHealth (){
    <#
    .SYNOPSIS
    Verifies health of WMI
    .DESCRIPTION
    Attempts to read WMI and write to namespaces recursively along with basic WMI health checks and returns boolean value
    .EXAMPLE
    Test-CHWMIHealth
    .PARAMETER strNamespace
    String value for the namespace requested for reading
    #>
    
    Write-CHLog "Test-CHWMIHealth" "Running winmgmt /verifyrepository"

    #attempt to verify WMI repository
    $null = winmgmt /verifyrepository
    if($lastexitcode -ne 0){
        Write-CHLog  "Test-CHWMIHealth" "Result of WMI repository check is not consistent"
        return $False
    }
    else{
        #get value of WMI repository corruption status
        [int]$intRepositoryCorrupt = Get-CHRegistryValue -strRegKey "HKLM:\SOFTWARE\Microsoft\Wbem\CIMOM" -strRegValue "RepositoryCorruptionReported"

        if($intRepositoryCorrupt -eq 0){
            Write-CHLog "Test-CHWMIHealth" "Result of WMI repository check is $intRepositoryCorrupt"
            Try{
                #attempt to read a core class from root\cimv2 namespace
                Get-WmiObject win32_operatingsystem -ErrorAction Stop | Out-Null

                if($global:objClientSettings.WMIWriteRepository -eq $true){
                    #basic test of WMI deems initial success
                    if($intRepositoryCorrupt -eq 0 -and (Test-CHWriteWMI "root\cimv2")){
                                                
                        #If SCCM client is installed, verify WMI core namespace health
                        if($global:blnSCCMInstalled -eq $true){
                            #continue testing by attempting write to all CCM namespaces
                            [array]$arrCCMNamespaces = gwmi -namespace root\ccm __namespace -recurse
                            [boolean]$blnStatus = $True
                            ForEach($arrCCMNamespace in $arrCCMNamespaces){
                                if(!(Test-CHWriteWMI "$($arrCCMNamespace.__NAMESPACE)\$($arrCCMNamespace.Name)")){
                                    $blnStatus = $False
                                }
                            }
                            if(!($blnStatus)){
                                Write-CHLog "Test-CHWMIHealth" "Unable to write to one or more namespaces in the SCCM namespace root\ccm" 
                            }
                            return $blnStatus
                        }
                        else{ return $true }
                    }
                    else{
                        Write-CHLog "Test-CHWMIHealth" "Failed to write to default WMI namespace or WMI is corrupt; rebuild of WMI is suggested"
                        return $False
                    }
                }
            }
            Catch{
                Write-CHLog "Test-CHWMIHealth" "Failed to get basic WMI information"
                return $False
            }
        }
        else{
            Write-CHLog "Test-CHWMIHealth" "ERROR: WMI is corrupt; rebuild of WMI is suggested"
            return $False
        }
    }
}

Function Get-CHServiceStatus()
{
    <#
    .SYNOPSIS
    Validate service status and start type.
    
    .DESCRIPTION
    Checks to make sure that a service start type and current status match what is supplied via command line parameter
    
    .EXAMPLE
    Get-CHServiceStatus -strServiceName BITS -strStartType DelayedAuto -strStatus Running

    .PARAMETER strServiceName
    String Value. The Name of the service in which to check status

    .PARAMETER strStartType
    The start type the service is expected to be in.
    Automatic
    Manual 
    Disabled 
    DelayedAuto 

    .PARAMETER strStatus
    Checks the to validate the service is in a specific state of Running or Stopped.  The value of NotMonitored will perform the check ignoring the state.

   .DEPENDENT FUNCTIONS
    Write-CHLog
    
    #>

    PARAM(
        [Parameter(Mandatory=$True)][string]$strServiceName,
        [Parameter(Mandatory=$True)][ValidateSet('Automatic','Manual','Disabled','DelayedAuto','NotDisabled')][string]$strStartType,
        [Parameter(Mandatory=$True)][ValidateSet('Running','Stopped','NotMonitored')][string]$strStatus 
    )

    #Convert friendly parameter to numeric values
    Switch ($strStartType)
    {
        "DelayedAuto"  {[int]$intExpectedStart = 2}
        "Automatic" {[int]$intExpectedStart = 2}
        "Manual"    {[int]$intExpectedStart = 3}
        "Disabled"  {[int]$intExpectedStart = 4}
        "NotDisabled"  {[int]$intExpectedStart = 0}
    }

    #Bind to the Service object using PoSH Get-Service
    $objService = Get-Service -Name $strServiceName -ErrorAction SilentlyContinue
    
    #Check to make sure there is a service that was found.
    if($objService){
        
        #Validate that the Automatic Services are configured correctly
        if($intExpectedStart -eq 2){
            #Get the Delayed AutoStart value from the Registry as this is the only way to tell the difference between Automatic and DelayedAuto
            [int]$intDelayedAutoStart = Get-CHRegistryValue "HKLM:\SYSTEM\CurrentControlSet\services\$strServiceName" "DelayedAutostart"

            #Validate Automatic is not set for DelyedAutoStart
            if($strStartType -eq "Automatic" -and $intDelayedAutoStart -eq 1){
                Write-CHLog -strFunction "Get-CHServiceStatus" -strMessage "WARNING - $strServiceName service is set to Delayed AutoStart and not expected."
                Return $False
            }
            
            #Validate Delayed Autostart is set correctly
            if($strStartType -eq "DelayedAuto" -and $intDelayedAutoStart -ne 1){
                Write-CHLog -strFunction "Get-CHServiceStatus" -strMessage "WARNING - $strServiceName is expecting Delayed Autostart, however is not configured correctly."
                Return $False
            }
        }

        #Get Start Type because the Get-Service does not show this and using WMI could be an issue on some machines.
        # 2=Automatic, 3=Manual, 4=Disabled
        [int]$intCurrentStart = Get-CHRegistryValue "HKLM:\SYSTEM\CurrentControlSet\services\$strServiceName" "Start"
        
        #Check StartType and Status match what is expected
        if(($intExpectedStart -eq $intCurrentStart -and $strStatus -eq $objService.Status) -or ($intExpectedStart -eq $intCurrentStart -and $strStatus -eq "NotMonitored") -or ($intCurrentStart -ne 4 -and $intExpectedStart -eq 0)){
            Write-CHLog -strFunction "Get-CHServiceStatus" -strMessage "$strServiceName is configured correctly."
            Return $True
        }
        else{
            Write-CHLog -strFunction "Get-CHServiceStatus" -strMessage "WARNING - $strServiceName Service not configured correctly"
            Write-CHLog -strFunction "Get-CHServiceStatus" -strMessage "WARNING - $strServiceName is expected to be set to $strStartType and currently $strStatus."

            #Output some helpful information if the current start type does not match the expected start type
            Switch ($intCurrentStart)
            {
                2 {Write-CHLog -strFunction "Get-CHServiceStatus" -strMessage "WARNING - $strServiceName is set to Automatic and status is currently $($objService.Status)"}
                3 {Write-CHLog -strFunction "Get-CHServiceStatus" -strMessage "WARNING - $strServiceName is set to Manual and status is currently $($objService.Status)"}
                4 {Write-CHLog -strFunction "Get-CHServiceStatus" -strMessage "WARNING - $strServiceName is set to Disabled and status is currently $($objService.Status)"}
            }

            Return $False
        }
    }
    else{
         Write-CHLog -strFunction "Get-CHServiceStatus" -strMessage "ERROR - $strServiceName service does not exist as an installed service on this computer."
         Return $False
    }

}

Function Set-CHServiceStatus()
{
    <#
    .SYNOPSIS
    Sets a service status and start type.
    
    .DESCRIPTION
     Sets the service start type and current status match what is supplied via command line parameter
    
    .EXAMPLE
    Set-CHServiceStatus -strServiceName BITS -strStartType Manual -strStatus Running

    .PARAMETER strServiceName
    String Value.The Name of the service in which to set

    .PARAMETER strStartType
    The start type the service is expected to be in.
    Automatic
    Manual 
    Disabled 
    DelayedAuto 

    .PARAMETER strStatus
    The status of the desired service, should be either Running or Stopped.

    .DEPENDENT FUNCTIONS
    Write-CHLog
    Get-CHServiceStatus

     #>

    PARAM(
        [Parameter(Mandatory=$True)][string]$strServiceName,
        [Parameter(Mandatory=$True)][ValidateSet('Automatic','Manual','Disabled','DelayedAuto')][String]$strStartType,
        [Parameter(Mandatory=$True)][ValidateSet('Running','Stopped')][string]$strStatus 
    )

    #Clear any errors
    $Error.Clear()
    
    #Convert friendly parameter to values for the SC command
    Switch ($strStartType)
    {
        "DelayedAuto"  {[string]$strStartTypeSC = "delayed-auto"}
        "Automatic" {[string]$strStartTypeSC = "auto"}
        "Manual"    {[string]$strStartTypeSC = "demand"}
        "Disabled"  {[string]$strStartTypeSC = "disabled"}
    }

    #Configure the Windows Service Start type and Status   
     Try{
        Write-CHLog -strFunction "Set-CHServiceStatus" -strMessage "Attempting to set $strServiceName to $strStartType and $strStatus"

        #Run SC command because start-service does not support Auto delayed
        [int]$intExitCode = (Start-Process -FilePath "$env:windir\system32\sc.exe" -ArgumentList "config $strServiceName start= $strStartTypeSC" -WindowStyle Hidden -PassThru -Wait).ExitCode

        If($intExitCode -eq 0){
            #Start or Stop Service based on request
            If($strStatus -eq "Running") {Start-Service -Name $strServiceName -ErrorAction Stop }
            If($strStatus -eq "Stopped") {Stop-Service -Name $strServiceName -ErrorAction Stop }

            #Check the Service Status
            $blnServiceStatus = Get-CHServiceStatus -strServiceName $strServiceName -strStartType $strStartType -strStatus $strStatus

            If($blnServiceStatus){
                Write-CHLog -strFunction "Set-CHServiceStatus" -strMessage "$strServiceName successfully set to $strStartType and $strStatus."

                Return $True
            }
            Else{
                Write-CHLog -strFunction "Set-CHServiceStatus" -strMessage "ERROR - $strServiceName Service was not configured correctly."
                Return $False
            }
        }
        Else{
            Write-CHLog -strFunction "Set-CHServiceStatus" -strMessage "ERROR - Could not set $strServiceName to a starttype of $strStartType.  Exit Code ($intExitCode)"
            Return $False
        }
     }
     Catch{
        #Get first line of error only
        [string]$strErrorMsg = ($Error[0].toString()).Split(".")[0]

        #Catch any error and write tolog
        Write-CHLog -strFunction "Set-CHServiceStatus" -strMessage "ERROR - $strServiceName Service not configured correctly.  $strErrorMsg"

        Return $False
     }
   
}

Function Invoke-CHWMIRebuild (){
    <#
    .SYNOPSIS
    Initiated when WMI Rebuild is required
    .DESCRIPTION
    In depth rebuild of Windows Management Instrumentation (WMI)
    .EXAMPLE
    Invoke-CHWMIRebuild
    .EXAMPLE
    Invoke-CHWMIRebuild
    #>
    
    if($global:blnDebug){ Write-CHLog "Invoke-CHWMIRebuild" "Information: Starting the process of rebuilding WMI" }

    [string]$strWbemPath = "$($env:WINDIR)\system32\wbem"
    [string]$strRepository = "$strWbemPath\Repository"

    if($global:blnDebug){ Write-CHLog "Invoke-CHWMIRebuild" "Information: Stop SMS Agent Host if it exists" }
    Try{
        Get-Service -Name CcmExec -ErrorAction Stop | Stop-Service -ErrorAction Stop | Out-Null
        if($global:blnDebug){ Write-CHLog "Invoke-CHWMIRebuild" "Information: Stop SMS Agent Host service was successful" }
    }
    Catch{
        Write-CHLog "Invoke-CHWMIRebuild" "Warning: Stop SMS Agent Host service was not successful"
    }

    #stop CCMSETUP process and delete service if it exists
    if($global:blnDebug){ Write-CHLog "Invoke-CHWMIRebuild" "Information: Stop CCMSETUP Service and delete if it exists" }

    if((Get-Service -Name ccmsetup -ErrorAction SilentlyContinue) -ne $null){
        Get-Process -Name ccmsetup -ErrorAction SilentlyContinue | Stop-Process -ErrorAction SilentlyContinue -Force | Out-Null
                
        #delete the ccmsetup service
        [object]$objStatus = Start-Process -FilePath "$env:windir\system32\sc.exe" -ArgumentList "delete ccmsetup" -WindowStyle Hidden -PassThru -Wait
        if($objStatus.ExitCode -eq 0){
            if($global:blnDebug){ Write-CHLog "Invoke-CHWMIRebuild" "Information: CCMSETUP service was deleted" }
        }
        else{
            Write-CHLog "Invoke-CHWMIRebuild" "Warning: CCMSETUP service was not deleted; continuing to repair WMI"
        }

        #cleaning up variable
        Remove-Variable "objStatus"
    }

    #uninstall SCCM client if the service exists
    if(Get-Service ccmexec -ErrorAction SilentlyContinue){ Invoke-CHClientAction -strAction Uninstall }

    #reset security on the WMI, Windows Update, and BITS services
    [array]$arrServices = @("winmgmt","wuauserv","bits")
                
    foreach($strService in $arrServices){
        Write-CHLog "Invoke-CHWMIRebuild" "Information: The current security descriptor for the $strService Service is $(sc.exe sdshow $strService)"
        Write-CHLog "Invoke-CHWMIRebuild" "Information: Setting default security descriptor on $strService to D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)"
        [object]$objStatus = Start-Process -FilePath "$env:windir\system32\sc.exe" -ArgumentList "sdset $strService D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)" -WindowStyle Hidden -PassThru -Wait
        Write-CHLog "Invoke-CHWMIRebuild" "Information: The exit code to set the security descriptor is $($objStatus.ExitCode)"
    }

    #cleaning up variable
    Remove-Variable "objStatus"

    #Re-enabling DCOM
    if(Set-CHRegistryValue "HKLM:\SOFTWARE\Microsoft\OLE" -strRegValue "EnableDCOM" -strData "Y" -strDataType "string"){
        if($global:blnDebug){ Write-CHLog "Invoke-CHWMIRebuild" "Information: Successfully enabled DCOM" }
    }
    else{ Write-CHLog "Invoke-CHWMIRebuild" "Warning: DCOM not enabled successfully" }

    #Resetting DCOM Permissions
    Write-CHLog "Invoke-CHWMIRebuild" "Information: Resetting DCOM Permissions"
                
    [array]$arrRegEntries = @("DefaultLaunchPermission","MachineAccessRestriction","MachineLaunchRestriction")
    foreach($strRegEntry in $arrRegEntries){
        [object]$objStatus = Start-Process -FilePath "$env:windir\system32\reg.exe" -ArgumentList "delete HKLM\software\microsoft\ole /v $strRegEntry /f" -WindowStyle Hidden -PassThru -Wait
        Write-CHLog "Invoke-CHWMIRebuild" "Information: The exit code to delete $strRegEntry from HKLM:\software\microsoft\ole is $($objStatus.ExitCode)"
    }

    #Rebuild WMI using WINMGMT utility (supported in each OS with version 6 or higher)
    if($global:blnDebug){ Write-CHLog "Invoke-CHWMIRebuild" "Refreshing WMI ADAP" }
    [object]$objStatus = Start-Process -FilePath "$strWbemPath\wmiadap.exe" -ArgumentList "/f" -WindowStyle Hidden -PassThru -Wait
    Write-CHLog "Invoke-CHWMIRebuild" "Information: The exit code to Refresh WMI ADAP is $($objStatus.ExitCode)"

    if($global:blnDebug){ Write-CHLog "Invoke-CHWMIRebuild" "Registering WMI" }
    [object]$objStatus = Start-Process -FilePath "$env:windir\system32\regsvr32.exe" -ArgumentList "/s wmisvc.dll" -WindowStyle Hidden -PassThru -Wait
    Write-CHLog "Invoke-CHWMIRebuild" "Information: The exit code to Register WMI is $($objStatus.ExitCode)"

    if($global:blnDebug){ Write-CHLog "Invoke-CHWMIRebuild" "Resyncing Performance Counters" }
    [object]$objStatus = Start-Process -FilePath "$strWbemPath\winmgmt.exe" -ArgumentList "/resyncperf" -WindowStyle Hidden -PassThru -Wait
    Write-CHLog "Invoke-CHWMIRebuild" "Information: The exit code to Resync Performance Counters is $($objStatus.ExitCode)"

    if($global:blnDebug){ Write-CHLog "Invoke-CHWMIRebuild" "Attempting salvage of WMI repository using winmgmt /salvagerepository" }
    [object]$objStatus = Start-Process -FilePath "$strWbemPath\winmgmt.exe" -ArgumentList "/salvagerepository" -WindowStyle Hidden -PassThru -Wait
    Write-CHLog "Invoke-CHWMIRebuild" "Information: The exit code to Salvage the WMI Repository is $($objStatus.ExitCode)"

    #unregistering atl.dll
    [object]$objStatus = Start-Process -FilePath "$env:windir\system32\regsvr32.exe" -ArgumentList "/u $env:windir\system32\atl.dll /s" -WindowStyle Hidden -PassThru -Wait
    Write-CHLog "Invoke-CHWMIRebuild" "Information: The exit code to Unregister ATL.DLL is $($objStatus.ExitCode)"

    #registering required DLLs
    [array]$arrDLLs = @("scecli.dll","userenv.dll","atl.dll")
                
    foreach($strDll in $arrDLLs){
        [object]$objStatus = Start-Process -FilePath "$env:windir\system32\regsvr32.exe" -ArgumentList "/s $env:windir\system32\$strDll" -WindowStyle Hidden -PassThru -Wait
        Write-CHLog "Invoke-CHWMIRebuild" "Information: The exit code to Register $strDLL is $($objStatus.ExitCode)"
    }

    #Register WMI Provider
    [object]$objStatus = Start-Process -FilePath "$strWbemPath\wmiprvse.exe" -ArgumentList "/regserver" -WindowStyle Hidden -PassThru -Wait
    Write-CHLog "Invoke-CHWMIRebuild" "Information: The exit code to Register WMI Provider is $($objStatus.ExitCode)"
    
    #Restart WMI Service
    Try{
        Write-CHLog "Invoke-CHWMIRebuild" "Restarting the WMI Service"
        
        [string]$strSvcName = "winmgmt"
        
        # Get dependent services
        [array]$arrDepSvcs = Get-Service -name $strSvcName -dependentservices | Where-Object {$_.Status -eq "Running"} | Select -Property Name
 
        # Check to see if dependent services are started
        if ($arrDepSvcs -ne $null) {
	        # Stop dependencies
	        foreach ($objDepSvc in $arrDepSvcs)
	        {
                Write-CHLog "Invoke-CHWMIRebuild" "Stopping $($objDepSvc.Name) as it is a dependent of the WMI Service"
		        Stop-Service $objDepSvc.Name -ErrorAction Stop | Out-Null
		        do
		        {
			        [object]$objService = Get-Service -name $objDepSvc.Name | Select -Property Status
			        Start-Sleep -seconds 1
		        }
		        until ($objService.Status -eq "Stopped")
	        }
        }
 
        # Restart service
        Restart-Service $strSvcName -force -ErrorAction Stop | Out-Null
        do
        {
	        $objService = Get-Service -name $strSvcName | Select -Property Status
	        Start-Sleep -seconds 1
        }
        until ($objService.Status -eq "Running")
                
        # We check for Auto start flag on dependent services and start them even if they were stopped before
        foreach ($objDepSvc in $arrDepSvcs)
        {
	        $objStartMode = gwmi win32_service -filter "NAME = '$($objDepSvc.Name)'" | Select -Property StartMode
	        if ($objStartMode.StartMode -eq "Auto") {
		        
                Write-CHLog "Invoke-CHWMIRebuild" "Starting $($objDepSvc.Name) after restarting WMI Service"
                Start-Service $objDepSvc.Name -ErrorAction Stop | Out-Null
		        do
		        {
			        $objService = Get-Service -name $objDepSvc.Name | Select -Property Status
			        Start-Sleep -seconds 1
		        }
		        until ($objService.Status -eq "Running")
	        }
        }
    }
    Catch{
        Write-CHLog "Invoke-CHWMIRebuild" "ERROR - Restart of WMI service failed"
    }

    Write-CHLog "Invoke-CHWMIRebuild" "ACTION: Rebuild of WMI completed; please reboot system"

    #Run GPUpdate if on Domain
    if((Get-CHRegistryValue "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters" "Domain") -ne ""){
        gpupdate | Out-Null
    }
    
    Write-CHLog "Invoke-CHWMIRebuild" "Testing WMI Health post repair"

    if(Test-CHWMIHealth -eq $False){
        Write-CHLog "Invoke-CHWMIRebuild" "ERROR - WMI Verification failed; reseting the repository with winmgmt /resetrepository"

        [object]$objStatus = Start-Process -FilePath "$strWbemPath\winmgmt.exe" -ArgumentList "/resetrepository" -WindowStyle Hidden -PassThru -Wait
        Write-CHLog "Invoke-CHWMIRebuild" "Information: The exit code to Reset the WMI Repository is $($objStatus.ExitCode)"

        if($objStatus.ExitCode -eq 0){
            Write-CHLog "Invoke-CHWMIRebuild" "WMI reset successfully; verifying repository again"

            if(Test-CHWMIHealth -eq $false){
                Write-CHLog "Invoke-CHWMIRebuild" "ERROR - WMI Verification failed after reseting the repository with winmgmt /resetrepository"
                [boolean]$blnWMIHealth = $false
            }
            else{
                [boolean]$blnWMIHealth = $true
            }
        }
    }
    else{ [boolean]$blnWMIHealth = $true }

    #increment WMI rebuild count by 1 and write back to registry; it is important to track this number no matter success or failure of the rebuild
    [int]$intWMIRebuildCount = 1 + (Get-CHRegistryValue $global:strPFEKeyPath "PFE_WMIRebuildAttempts")
    Set-CHRegistryValue $global:strPFEKeyPath "PFE_WMIRebuildAttempts" $intWMIRebuildCount "string"

    Write-CHLog "Invoke-CHWMIRebuild" "Information: WMI has been rebuilt $intWMIRebuildCount times by the PFE Remediation for Configuration Manager script"

    if($blnWMIHealth){
        Write-CHLog "Invoke-CHWMIRebuild" "Information: WMI Verification successful after reseting the repository with winmgmt /resetrepository"

        if($global:blnDebug){ Write-CHLog "Invoke-CHWMIRebuild" "Information: Detecting Microsoft Policy Platform installation; if installed will attempt to compile MOF/MFL files" }
        if($global:blnDebug){ Write-CHLog "Invoke-CHWMIRebuild" "Information: This is done to prevent ccmsetup from erroring when trying to compile DiscoveryStatus.mof and there are issues with the root\Microsoft\PolicyPlatform namespace" }

        if(Test-Path "$env:ProgramFiles\Microsoft Policy Platform" -ErrorAction SilentlyContinue){
            [array]$arrMPPFiles = Get-ChildItem "$env:ProgramFiles\Microsoft Policy Platform" | where { ($_.Extension -eq ".mof" -or $_.Extension -eq ".mfl") -and $_.Name -notlike "*uninst*" } | foreach { $_.fullname }
            foreach($strMPPFile in $arrMPPFiles){
                        
                [object]$objStatus = Start-Process -FilePath "$strWbemPath\mofcomp.exe" -ArgumentList """$strMPPFile""" -WindowStyle Hidden -PassThru -Wait
                Write-CHLog "Invoke-CHWMIRebuild" "Information: The exit code to MOFCOMP $strMPPfile is $($objStatus.ExitCode)"
            }
        }
        else{
            Write-CHLog "Invoke-CHWMIRebuild" "Warning: Unable to get Microsoft Policy Platform files"
        }
        return $True
    }
    else { return $false }
}

Function Invoke-CHClientAction (){
    
    <#
	.SYNOPSIS
	Install, uninstall, or repair the SCCM client

	.DESCRIPTION
	Function to install the most current version of the SCCM client

	.EXAMPLE
	Invoke-CHClientAction -strAction Install

    .DEPENDENT FUNCTIONS
    Write-CHLog
    Set-CHRegistryValue
    Get-CHRegistryValue

    .PARAMETER strAction
    The name of the client action to be taken
    #>
    
    param
    (
        [Parameter(Mandatory=$True,
        ValueFromPipelineByPropertyName=$True)]
        [ValidateSet('Install','Uninstall','Repair')][string]$strAction
    )

    Write-CHLog -strFunction "Invoke-CHClientAction" -strMessage "The client action $strAction has been initiated"

    If(($global:objClientSettings.WorkstationRemediation -eq $TRUE -and $global:strOSType -eq 'workstation') -or ($global:objClientSettings.ServerRemediation -eq $TRUE -and $global:strOSType -eq 'server')) {
        
        Write-CHLog -strFunction "Invoke-CHClientAction" -strMessage "Remediation enabled; beginning ConfigMgr client $strAction"

        #Get current Date and Time
        Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_LastAction" -strData "Client $strAction" -strDataType string
        Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_LastDate" -strData (Get-Date -format yyyy-MM-dd) -strDataType string
        Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_LastTime" -strData (Get-Date -format HH:mm:ss) -strDataType string
        
        Stop-Service -Name "CCMSetup" -Force -ErrorAction SilentlyContinue
        Stop-Process -Name "CCMSetup" -Force -ErrorAction SilentlyContinue
        Stop-Process -Name "CCMRestart" -Force -ErrorAction SilentlyContinue

        if(Test-Path "c:\windows\ccmsetup\ccmsetup.exe"){
            [string]$strClientActionCommand = "c:\windows\ccmsetup\ccmsetup.exe"
        }
        else{ [string]$strClientActionCommand = "\\$($global:objClientSettings.PrimarySiteServer)\Client$\ccmsetup.exe" }

        #Convert friendly parameter to values for the SC command
        Switch ($strAction)
        {
            "Install"   {[string]$strClientActionArgs = "$($global:objClientSettings.ExtraEXECommands) SMSSITECODE=$($global:strSiteCode) $($global:objClientSettings.ExtraMSICommands)"}
            "Uninstall" {[string]$strClientActionArgs = "/Uninstall"}
            "Repair"    {[string]$strClientActionArgs = "$($global:objClientSettings.extraEXECommands) SMSSITECODE=$($global:strSiteCode) RESETKEYINFORMATION=TRUE REMEDIATE=TRUE $($global:objClientSettings.extraMSICommands)"}
        }

        Write-CHLog -strFunction "Invoke-CHClientAction" -strMessage "Starting Client $strAction with command line $strClientActionCommand $strClientActionArgs"
        
        [int]$intClientActionExitCode = (Start-Process $strClientActionCommand -ArgumentList $strClientActionArgs -wait -NoNewWindow -PassThru ).ExitCode

        if($strAction -ne "Uninstall"){
            if(($intClientActionExitCode -eq 0) -and ($strClientActionArgs.ToLower() -contains "/noservice")){
                #Client install complete
                Write-CHLog -strFunction "Invoke-CHClientAction" -strMessage "$strAction of ConfigMgr Client complete"
                return $true
            }
            elseif(($intClientActionExitCode -eq 0) -and ($strClientActionArgs.ToLower() -notcontains "/noservice")){
                #client installing
                Write-CHLog -strFunction "Invoke-CHClientAction" -strMessage "$strAction of ConfigMgr Client has begun"
                Start-Sleep -Seconds 30
                [string]$strProcessID = Get-Process -name "ccmsetup" -ErrorAction SilentlyContinue | foreach {$_.Id}
                if($strProcessID.Trim() -eq ""){
                    Write-CHLog -strFunction "Invoke-CHClientAction" -strMessage "No Process ID found for CCMSETUP"
                    Write-CHLog -strFunction "Invoke-CHClientAction" -strMessage "ERROR - CCMSETUP not launched successfully, validate command line is correct"
                    return $false
                }
                else{
                    Write-CHLog -strFunction "Invoke-CHClientAction" -strMessage "Monitoring Process ID $strProcessID for CCMSETUP to complete"
                    Write-CHLog -strFunction "Invoke-CHClientAction" -strMessage "ConfigMgr client $strAction is running"
                    Wait-Process -Id $strProcessID
                    Write-CHLog -strFunction "Invoke-CHClientAction" -strMessage "ConfigMgr client $strAction complete"

                    #Service Startup Checks
                    try{
                        Get-Process -name "ccmexec" -ErrorAction Stop | Out-Null
                        Get-Service -name "ccmexec" -ErrorAction Stop | Out-Null

                        return $true
                    }
                    catch{
                        Write-CHLog -strFunction "Invoke-CHClientAction" -strMessage "ERROR - Service check after client $strAction failed"
                        return $false
                    }
                    #Detect Application that needs to install
                }
            }
            else{
                #client install failed
                Write-CHLog -strFunction "Invoke-CHClientAction" -strMessage "ERROR - $strAction of ConfigMgr Client has failed"
                return $false
            }
        }
        else{
            if($intClientActionExitCode -eq 0) {
                Write-CHLog -strFunction "Invoke-CHClientAction" -strMessage "System Center ConfigMgr Client successfully uninstalled"
                $global:blnSCCMInstalled = $false
                #If Policy Platform is installed, Remove it
                Try{
                    [string]$strFilePath = Get-ChildItem HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall | where-object { $_.GetValue("DisplayName") -eq "Microsoft Policy Provider" } | ForEach-Object { $_.GetValue("UninstallString") }
                    [string]$strProcessName = $strFilePath.Substring(0,$strFilePath.IndexOf(' '))
                    [string]$strArgList = $strFilePath.Substring($strFilePath.IndexOf('/'),$strFilePath.Length-$strFilePath.IndexOf('/'))
                    [int]$intPolProvUninstall = (Start-Process $strProcessName -ArgumentList $strArgList -wait -NoNewWindow -PassThru ).ExitCode
                    If($intPolProvUninstall -eq 0) {
                        Write-CHLog -strFunction "Invoke-CHClientAction" -strMessage "Microsoft Policy Platform successfully uninstalled"
                    }
                    Else {
                        Write-CHLog -strFunction "Invoke-CHClientAction" -strMessage "ERROR - Microsoft Policy Platform failed to uninstall with exit code $intPolProvUninstall"
                    }
                }
                Catch {
                    Write-CHLog -strFunction "Invoke-CHClientAction" -strMessage "ERROR - Could not bind to registry to do uninstall of Microsoft Policy Platform.  Either cannot access registry, or the MPP is not installed"
                }
            }
            Else {
                Write-CHLog -strFunction "Invoke-CHClientAction" -strMessage "ERROR - Failed to uninstall System Center ConfigMgr Client"
            }
        }
    }
    else {
        Write-CHLog -strFunction "Invoke-CHClientAction" -strMessage "WARNING - Remediation has been disabled for this hardware type. Will not $strAction client"
        return $false
    }

    #Update Registry with current status and date\time
    Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_LastAction" -strData "Client $strAction" -strDataType string
    Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_LastDate" -strData (Get-Date -format yyyy-MM-dd) -strDataType string
    Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_LastTime" -strData (Get-Date -format HH:mm:ss) -strDataType string
}

Function Test-CHStaleLog() {
<#
    .SYNOPSIS
    Checks to see whether the specified log file has shown activity within the provided timeframe.
    
    .DESCRIPTION
    This function will check to see if a log file has been written to in a certain amount of time.  If it has not,
    a repair will be run on the client.  If the log file does not exist, a repair will be run on the client if there
    has not been activity in the ccmsetup log within the last 24 hours.

    Return value will be boolean based and a TRUE should flag a CCMRepair.
    
    .EXAMPLE
    Test-CHStaleLog -strLogFileName ccmexec -intDaysStale 2

    .PARAMETER strLogFileName
    File name of the log that would would like to test for inactivity.  Name should NOT include the '.log' at the end.

    .PARAMETER intDaysStale
    Number of days of inactivity that you would consider the specified log stale.

    
    .DEPENDENT FUNCTIONS
    Write-CHLog
    Set-CHRegistryValue
    Get-CHRegistryValue

    #>

    PARAM(
         [Parameter(Mandatory=$True,
        ValueFromPipelineByPropertyName=$True)]
        [string]$strLogFileName,

        [Parameter(Mandatory=$True,
        ValueFromPipelineByPropertyName=$True)]
        [int]$intDaysStale

    )
    
    Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_LastAction" -strData "Stale Logs" -strDataType string
    Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_LastDate" -strData (Get-Date -format yyyy-MM-dd) -strDataType string
    Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_LastTime" -strData (Get-Date -format HH:mm:ss) -strDataType string

    #get log file location from registry
    [string]$strCMInstallKey = 'HKLM:\SOFTWARE\Microsoft\CCM\Logging\@Global'
    [string]$strCMClientInstallLog = 'C:\Windows\ccmsetup\Logs\ccmsetup.log'
    
    if(Test-Path $strCMInstallKey){
        [string]$strCMInstallLocation = Get-CHRegistryValue -strRegKey $strCMInstallKey -strRegValue 'LogDirectory'

        [string]$strLog = "$strCMInstallLocation\$strLogFileName.log"
        Write-CHLog -strFunction "Test-CHStaleLog" -strMessage "Check $strLog for activity"

        if(Test-Path $strLog) {
            [datetime]$dtmLogDate = (Get-Item $strLog).LastWriteTime
            [int]$intDaysDiff = (New-TimeSpan $dtmLogDate (Get-Date -format yyyy-MM-dd)).Days
            if($intDaysDiff -gt $intDaysStale) {
                #Unhealthy
                Write-CHLog -strFunction "Test-CHStaleLog" -strMessage "$strLogFileName.log is not active"
                Write-CHLog -strFunction "Test-CHStaleLog" -strMessage "$strLogFileName.log last date modified is $strLogDate"
                Write-CHLog -strFunction "Test-CHStaleLog" -strMessage "Current Date and Time is $(get-date)"
                return $true
            }
            else{
                #Healthy
                Write-CHLog -strFunction "Test-CHStaleLog" -strMessage "$strLogFileName.log is active"
                return $false
            }
        }
        else{
            #Log File Missing
            Write-CHLog -strFunction "Test-CHStaleLog" -strMessage "$strLogFileName.log is missing; checking for recent ccmsetup activity"
            if(Test-Path $strCMClientInstallLog) {
                [datetime]$dtmCMClientInstallLogDate = (Get-Item $strCMClientInstallLog).LastWriteTime
                [int]$intClientInstallHours = (New-TimeSpan (Get-Date -format yyyy-MM-dd) $dtmCMClientInstallLogDate).TotalHours
                if($intClientInstallHours -lt 24) {
                    #Log has been written to recently / client has been installed recently
                    Write-CHLog -strFunction "Test-CHStaleLog" -strMessage "CCMSetup activity detected within last 24 hours, will not attempt to repair"
                    return $false
                }
                else{
                    #Log has not been written to recently / client has not been installed or repaired recently
                    Write-CHLog -strFunction "Test-CHStaleLog" -strMessage "CCMSetup activity not detected within last 24 hours, will attempt to repair"
                    return $true
                }
            }
            else{
                #Client Never Installed
                Write-CHLog -strFunction "Test-CHStaleLog" -strMessage "CCMSetup.log not found in $strCMClientInstallLog, will attempt to install client"
                return $true
            }
        }
    }
    else{
        Write-CHLog -strFunction "Test-CHStaleLog" -strMessage "Error - No log file directory found"
        return $true
    }
}

Function Get-CHini (){
    <#
    .SYNOPSIS
    Reads an ini file and returns back the value of the provided key
    .DESCRIPTION
    Parses through a provided ini file and finds the value of a key under a particular section of the file
    .EXAMPLE
    Get-CHINI -parameter "value"
    .EXAMPLE
    Get-CHINI -strFile "c:\Windows\smscfg.ini" -strSection "Configuration - Client Properties" -strKey "SID"
    .PARAMETER strFile
    Full path to desired ini file
    .PARAMETER strSection
    Section name from the ini file where the requested key is located
    .PARAMETER strKey
    Key name of requested value
     #>
    param
    (
        [Parameter(Mandatory=$True,
        ValueFromPipelineByPropertyName=$True)]
        [string]$strFile,

        [Parameter(Mandatory=$True,
        ValueFromPipelineByPropertyName=$True)]
        [string]$strSection,
        
        [Parameter(Mandatory=$True,
        ValueFromPipelineByPropertyName=$True)]
        [string]$strKey

    )
 
    <#Test settings to run without function call
	$strFile = "c:\Windows\smscfg.ini"
    $strSection = "Configuration - Client Properties"
    $strKey = "SID"
	#>
        
    If(Test-Path $strFile) {
        Write-CHLog -strFunction "Get-CHINI" -strMessage "$strFile exists"
        Write-CHLog -strFunction "Get-CHINI" -strMessage "Searching for $strKey in [$strSection] section"
        [object]$objINI = New-Object psobject
               
        switch -regex -file $strFile {
            "^\[(.+)\]" { 
                $section = $matches[1]
            }#Section
            "(.+?)\s*=(.*)" {
                $name,$value = $matches[1..2]
                $objINI | Add-Member -MemberType NoteProperty -Name ("$section.$name") -Value $value
            }#Key
        }
    
        #$strValue = $arrINI[$strSection][$strKey]
        $strValue = $objINI.("$strSection.$strkey")
        If($strValue -eq $NULL) {
            Write-CHLog -strFunction "Get-CHINI" -strMessage "$strKey value is blank"
        }
        Else {
            Write-CHLog -strFunction "Get-CHINI" -strMessage "$strKey value found"
            Write-CHLog -strFunction "Get-CHINI" -strMessage "$strKey = $strValue"
            return $strValue
        }
    }

    Else {
        Write-CHLog -strFunction "Get-CHINI" -strMessage "$strFile does not exist"
    }
}

Function Test-CHAppPolicy()
{
    <#
    .SYNOPSIS
    Validate that all Application Policies that have been retrived by the machine are processed correctly.

    .DESCRIPTION
    Compare the CCM_ApplicaitonCIAssignments on the local machine to validate that all policies have been added to the ClientSDK.  
    In some instances the Lantern module can be corrupt and while there is a policy, the CI is not processed and added to the local database or WMI.
    This will cause the deployment to never run or evaluate.  
    The return will be a Boolean value of True or False indicating if the Check passed.

    .EXAMPLE
    Test-CHAppPolicy

    .DEPENDENT FUNCTIONS
 
     #>
    
    Try{
        #Create an arry of all the Application CI Assignments from the local Policy
        [array]$arrAppDeployments = $null
        [array]$arrAppDeployments = Get-WmiObject -Namespace root\CCM\Policy\Machine\ActualConfig -Query "Select * from CCM_ApplicationCIAssignment" -ErrorAction SilentlyContinue

        if($arrAppDeployments){
            #Create an array of all the Application Policy stored in the ClientSDK 
            [array]$arrAppPolicy = Get-WmiObject -Namespace root\CCM\ClientSDK -Query "SELECT * FROM CCM_ApplicationPolicy" -ErrorAction Stop

            #Loop through each AppDeployment Policy to see if it has an entry in the ClientSDK
        
            ForEach ($objAppDeployments in $arrAppDeployments){
                #Pull the Application Unique ID from the machine policy to use for comparison
                [string]$strCIXML = $objAppDeployments.AssignedCIs[0]
                [int]$intModelStart = $strCIXML.indexof("<ModelName>")
                [int]$intModelFinish = $strCIXML.indexof("</ModelName>")
                [string]$strCIID = $strCIXML.Substring($intModelStart + 11, $intModelFinish - ($intModelStart + 11))
        
                #Set to False and wait to be proven wrong
		        [bool]$blnAppPolicyMatch = $FALSE

                #Loop throgh each Application Policy in ClientSDK looking for a match
                ForEach ($objAppPolicy in $arrAppPolicy){
                    #If there is a match set AppPolicyMatch to true
                    If (($objAppPolicy.ID -eq $strCIID) -and ($objAppPolicy.IsMachineTarget)){$blnAppPolicyMatch=$TRUE}
                }

                #If we did not find a match, set Function to False and exit as it only takes one to error
                If(!($blnAppPolicyMatch)){
                    Write-CHLog -strFunction "Test-CHAppPolicy" -strMessage "Application Policy does not match Deployment Policy, possible CI Corruption."
                    Return $False
                }
            }
        }

        #If we made it through the loop without and error, then all policies exists
        Return $True
    }
    Catch{
        #Get first line of error only
        [string]$strErrorMsg = ($Error[0].toString()).Split(".")[0]

        Write-CHLog -strFunction "Test-CHAppPolicy" -strMessage "ERROR - Check Application policy failed with error ($strErrorMsg)"
        Return $False
    }
}

Function Test-CHAppIntentEval()
{
    <#
    .SYNOPSIS
    Check to see if the AppIntentEval log was modified in the last 5 minutes.
    
    .DESCRIPTION
    Check to see if the AppIntentEval log was modified in the last 5 minutes.
    Returns a boolean value of True or False.
    
    .EXAMPLE
    Test-CHAppIntentEval

    .DEPENDENT FUNCTIONS
    Write-CHLog
    #>

    #Get CM Client Installation Directory
    [string]$strCCMInstallDir = Get-CHRegistryValue "HKLM:\SOFTWARE\Microsoft\SMS\Client\Configuration\Client Properties" "Local SMS Path"
    
    If(($strCCMInstallDir) -and ($strCCMInstallDir -ne "Error")){
        #Set Variable for the Application Intent Evaluation log file
        [string]$strLogFile = $strCCMInstallDir + "Logs\AppIntentEval.log"

        #Validate Log file exists and if not cacle
        If (Test-Path -Path $strLogFile){
            #Get the Current Date and Time
            [datetime]$dtmCurrentDate = Get-Date

            #Get the last Modified time for the log file
            [datetime]$dtmModifiedDate = (Get-Item -Path $strLogFile).LastWriteTime
        
            Write-CHLog -strFunction "Test-CHAppIntentEval" -strMessage "Last Modified time for AppIntentEval is $dtmModifiedDate."
            Write-CHLog -strFunction "Test-CHAppIntentEval" -strMessage "Current Time is $dtmCurrentDate."

            #Get the time in minutes since the file was last modified
            [int]$intTimeSinceModified = (New-TimeSpan $dtmModifiedDate $dtmCurrentDate).TotalMinutes

            Write-CHLog -strFunction "Test-CHAppIntentEval" -strMessage "Last modified $intTimeSinceModified minutes ago."

            #If the time is less than 5 min exit with True.
            If($intTimeSinceModified -le 5){Return $True}

        }
        Else{
            #Log files does not exists.  This could be expected for newly installed clients.
            Write-CHLog -strFunction "Test-CHAppIntentEval" -strMessage " $strLogFile file does not exist.  No further action needed for AppIntentEval."
            Return $True
        }
    }
    Else{
        #exit if we cannot get an CCMInstall Directory from Registry
        Write-CHLog -strFunction "Test-CHAppIntentEval" -strMessage "Warning - Unable to find ConfigMgr Install Directory from Registry.  Exit function."
        Return $False
    }
    
    #If we got here without an exit it must be false
    Return $False
}

Function Test-CHLantern()
{
    <#
    .SYNOPSIS
    Check to see if ConfigMgr CI processing is working, aslo known as lantern.
    
    .DESCRIPTION
    Check to see if there is a conflict in the Application Policy received and stored in the WMI.  If an issue is found will kick off an Application
    Deployment Evaluation cycle to check to see that the AppIntentEval log is updated, if not this will identify an issue with Lantern processing.
    If found a client repair forcing the CCMStore.sdf file to be repaired is the only fix.

    Return value will be boolean based and a FALSE should flag a CCMRepair.
    
    .EXAMPLE
    Test-CHLantern

    .DEPENDENT FUNCTIONS
    Write-CHLog
    Test-CHAppPolicy
    Test-CHAppIntentEval

    #>

    Write-CHLog -strFunction "Test-CHLantern" -strMessage "Checking Application Policy."

    #Run Function to check Application Policy
    [bool]$blnAppPolicy = Test-CHAppPolicy

    #testing function by forcing a bad policy check.
    #$blnAppPolicy = $false

    #Check for Application Policy, if there is no Policy will assume everything is working.
    If (!($blnAppPolicy)){
        Write-CHLog -strFunction "Test-CHLantern" -strMessage "There was Application Policy conflict found.  Will trigger Application Deployment Evaluation."

        #Call Application Deployment Evaluation
        ([wmiclass]'root\ccm:SMS_Client').TriggerSchedule("{00000000-0000-0000-0000-000000000121}") | Out-Null

        #Sleep for 2 min to allow for Application Deployment to complete
        Write-CHLog -strFunction "Test-CHLantern" -strMessage "Waiting for 2 minutes to allow Application Deployment Evaluation to Complete."
        Start-Sleep -Seconds 120

        #Check if AppIntentEval.log is updated
        #[bool]$blnAppIntentUpdated = Test-CHAppIntentEval

        If(Test-CHAppIntentEval){
            #All is well, return healthy
            Write-CHLog -strFunction "Test-CHLantern" -strMessage "Client appears to be healthy.  Exiting Application Policy Check."
            Return $True
        }
        Else{
            #AppIntent Eval does not appear to be heatlhy.  Need to repair the client.
            Write-CHLog -strFunction "Test-CHLantern" -strMessage "Client does not appear to be healthy.  Requesting a repair of the client."

            #Repair CCM Client needed and force the ccmstore.sdf to be replaced
            Set-CHRegistryValue "HKLM:\SOFTWARE\Microsoft\CCMSetup" "CcmStore.sdf" -strData "corrupted" -strDataType string

            Return $False
        }
    }
    Else{
        #All is well, return healthy
        Write-CHLog -strFunction "Test-CHLantern" -strMessage "No Application Policy conflict found.  Client appears to be healthy."
        Return $True
    }
}

Function Invoke-CHACPInstall()
{
    <#
    .SYNOPSIS
    Install the Alternate Service Provider
    
    .DESCRIPTION
     Function to install the Alternate Service Provider after a ConfigMgr Client Reinstall \ Install.  The return will be a boolean value and if True the calling function should set ACP_Health = Healthy.
    
    .EXAMPLE
    Invoke-CHACPInstall

    .DEPENDENT FUNCTIONS
    Write-CHLog
    Get-CHServiceStatus
    Set-CHServiceStatus
    Set-CHRegistryValue

     #>

    PARAM(
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True)][string]$ACPSetup,
        [Parameter(Mandatory=$False,ValueFromPipelineByPropertyName=$True)][string]$ACPArguments,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True)][string]$ACPServiceName
    )

    #Clear any errors
    $Error.Clear()
    
    Write-CHLog -strFunction "Invoke-CHACPInstall" -strMessage "ACP Client needs to be installed."
    Write-CHLog -strFunction "Invoke-CHACPInstall" -strMessage "$ACPServiceName client will be repaired if remediation is enabled"

    #Write PFE Status to Registry
    Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_LastAction" -strData "ACP Repair" -strDataType string
    Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_LastDate" -strData (Get-Date -format yyyy-MM-dd) -strDataType string
    Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_LastTime" -strData (Get-Date -format HH:mm:ss) -strDataType string


    if(($global:strOSType -eq "workstation" -and $global:objClientSettings.WorkstationRemediation -eq $True) -or ($global:strOSType -eq "server" -and $global:objClientSettings.ServerRemediation -eq $True)){
        Try{
            #Check for commandline parameters
            If($ACPArguments -ne ""){
                 Write-CHLog -strFunction "Invoke-CHACPInstall" -strMessage "Installing ACP Client using the file $ACPSetup and commandline $ACPArguments."
            
                #Run the ACP Install command
                [object]$objProcess = Start-Process -FilePath "$ACPSetup" -ArgumentList "$ACPArguments" -WindowStyle Hidden -PassThru -Wait
                [int]$intExitCode = $objProcess.ExitCode
            }
            Else{
                 Write-CHLog -strFunction "Invoke-CHACPInstall" -strMessage "Installing ACP Client using the file $ACPSetup."
            
                #Run the ACP Install command
                [object]$objProcess = Start-Process -FilePath "$ACPSetup" -WindowStyle Hidden -PassThru -Wait
                [int]$intExitCode = $objProcess.ExitCode
            }

            #Check the status of the install
            If($intExitCode -eq 0){
                Write-CHLog -strFunction "Invoke-CHACPInstall" -strMessage "Installation of $ACPServiceName Client has completed, checking service status."

                #Installation is complete, now check to see if the service is started.
                If(Get-CHServiceStatus -strServiceName $ACPServiceName -strStartType $global:objClientSettings.ACPServiceStartType -strStatus Running){
                    Write-CHLog -strFunction "Invoke-CHACPInstall" -strMessage "Installation of $ACPServiceName Client has completed successfully."
            
                    #Write PFE Status to Registry
                    Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_ACPStatus" -strData "Healthy" -strDataType string
                    Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_LastDate" -strData (Get-Date -format yyyy-MM-dd) -strDataType string
                    Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_LastTime" -strData (Get-Date -format HH:mm:ss) -strDataType string

                    Return $True
                }
                Else{
                    If(Set-CHServiceStatus -strServiceName $ACPServiceName -strStartType $global:objClientSettings.ACPServiceStartType -strStatus Running){
                        Write-CHLog -strFunction "Invoke-CHACPInstall" -strMessage "Installation of $ACPServiceName Client has completed successfully."
                    
                        #Write PFE Status to Registry
                        Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_ACPStatus" -strData "Healthy" -strDataType string
                        Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_LastDate" -strData (Get-Date -format yyyy-MM-dd) -strDataType string
                        Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_LastTime" -strData (Get-Date -format HH:mm:ss) -strDataType string

                        Return $True
                    }
                    Else{
                        Write-CHLog -strFunction "Invoke-CHACPInstall" -strMessage "ERROR - Installation of $ACPServiceName client completed, but could not start the service."
                    
                        #Write PFE Status to Registry
                        Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_ACPStatus" -strData "UnHealthy" -strDataType string
                        Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_LastDate" -strData (Get-Date -format yyyy-MM-dd) -strDataType string
                        Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_LastTime" -strData (Get-Date -format HH:mm:ss) -strDataType string

                        Return $False
                    }
                }
            }
            Else{
                Write-CHLog -strFunction "Invoke-CHACPInstall" -strMessage "ERROR - Installation of $ACPServiceName Client has failed."

                #Write PFE Status to Registry
                Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_ACPStatus" -strData "UnHealthy" -strDataType string
                Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_LastDate" -strData (Get-Date -format yyyy-MM-dd) -strDataType string
                Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_LastTime" -strData (Get-Date -format HH:mm:ss) -strDataType string

                Return $False
            }
        }
        Catch{
            #Get first line of error only
            [string]$strErrorMsg = ($Error[0].toString()).Split(".")[0]

            #Catch any error and write tolog
            Write-CHLog -strFunction "Invoke-CHACPInstall" -strMessage "ERROR - $strErrorMsg"

            #Write PFE Status to Registry
            Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_ACPStatus" -strData "UnHealthy" -strDataType string
            Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_LastDate" -strData (Get-Date -format yyyy-MM-dd) -strDataType string
            Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_LastTime" -strData (Get-Date -format HH:mm:ss) -strDataType string

            Return $False
        }
    }
    else{
        Write-CHLog -strFunction "Invoke-CHACPInstall" -strMessage "WARNING - Remediation disabled"
        Write-CHLog -strFunction "Invoke-CHACPInstall" -strMessage "WARNING - $ACPServiceName will not be repaired"
    }
}

Function Invoke-CHBITSRepair()
{
    <#
    .SYNOPSIS
    Repair BITS service when it is found missing on the machine.
    
    .DESCRIPTION
    Performs a BITS repair.  This function is not currently called by the script.  Customers are willing to add logic manually.
        
    .EXAMPLE
    Invoke-CHBITSRepair -strStartType Manual -State Running

    .PARAMETER strStartType
    The start type the service is expected to be in.
    Automatic
    Manual 
    Disabled 
    DelayedAuto 

    .PARAMETER strStatus
    The status of the desired service, should be either Running or Stopped.

    
    .DEPENDENT FUNCTIONS
    Write-CHLog
    Get-CHServiceStatus
    Set-CHServiceStatus
    Set-CHRegistryValue
     #>

    PARAM(
        [Parameter(Mandatory=$True)][ValidateSet('Automatic','Manual','Disabled')][String]$strStartType,
        [Parameter(Mandatory=$True)][ValidateSet('Running','Stopped')][string]$strStatus 
    )


    Switch ($strStartType)
    {
        2 {[string]$strType = "auto"}
        3 {[string]$strType = "demand"}
        4 {[string]$strType = "disabled"}
    }

    Write-CHLog -strFunction "Invoke-CHBITSRepair" -strMessage "Starting BITS Repair.  BITS will be repaired."

    Try
    {    
        #Check to make sure BITS Registry Key exists
        [string]$strBITSPath = Get-CHRegistryValue -strRegKey "HKLM:\SYSTEM\CurrentControlSet\services\BITS" -strRegValue "ImagePath"  

        If (($strBITSPath -eq "Error") -or ($strBITSPath -eq $null))
        {
            Write-CHLog -strFunction "Invoke-CHBITSRepair" -strMessage "BITS Service Registry Key NOT found. Will not perform any further action."
    
            #Write PFE Status to Registry
            [string]$dtmDate = Get-Date -format yyyy-MM-dd
            [string]$dtmTime = Get-Date -format HH:mm:ss

            Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_BITSStatus" -strData "UnHealthy" -strDataType string
            Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_LastDate" -strData $dtmDate -strDataType string
            Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_LastTime" -strData $dtmTime -strDataType string

            Return $False

        }
        Else
        {
            Write-CHLog -strFunction "Invoke-CHBITSRepair" -strMessage "BITS Service Registry Key found."
            Write-CHLog -strFunction "Invoke-CHBITSRepair" -strMessage "Attempting to install BITS Service."

            #Get current Date and Time
            [datetime]$dtmDate = Get-Date -format yyyy-MM-dd
            [datetime]$dtmTime = Get-Date -format HH:mm:ss

            #Write Status to Registry
            Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_LastAction" -strData "BITS Repair" -strDataType string
            Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_LastDate" -strData $dtmDate -strDataType string
            Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_LastTime" -strData $dtmTime -strDataType string       

            #Run the sc to create the missing service command
            [string]$strArg = $env:windir + '\system32\svchost.exe -k netsvcs DisplayName= "Background Intelligent Transfer Service" start= ' + $strStartType

            $p = Start-Process -FilePath "$env:windir\system32\sc.exe" -ArgumentList $strArg -WindowStyle Hidden -PassThru -Wait
            [int]$intExitCode = $p.ExitCode

            #Check the return value
            If ($intResults -eq 0)
            {

                #Installation is complete, now check to see if the service is started.
                If(Get-CHServiceStatus -strServiceName "BITS" -strStartType $strStartType -strStatus Running) 
                {
                    Write-CHLog -strFunction "Invoke-CHBITSRepair" -strMessage "BITS Service Installation completed successfully."
            
                    #Write PFE Status to Registry
                    [string]$dtmDate = Get-Date -format yyyy-MM-dd 
                    [string]$dtmTime = Get-Date -format HH:mm:ss

                    Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_BITSStatus" -strData "Healthy" -strDataType string
                    Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_LastDate" -strData $dtmDate -strDataType string
                    Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_LastTime" -strData $dtmTime -strDataType string

                    Return $True
                }
                Else
                {
                    #Try to start the services
                    If(Set-CHServiceStatus -strServiceName "BITS" -strStartType $strStartType -strStatus Running)
                    {
                         Write-CHLog -strFunction "Invoke-CHBITSRepair" -strMessage "BITS Service Installation completed successfully."
                    
                        #Write PFE Status to Registry
                        [string]$dtmDate = Get-Date -format yyyy-MM-dd
                        [string]$dtmTime = Get-Date -format HH:mm:ss

                        Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_BITSStatus" -strData "Healthy" -strDataType string
                        Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_LastDate" -strData $dtmDate -strDataType string
                        Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_LastTime" -strData $dtmTime -strDataType string

                        Return $True
                    }
                    Else
                    {
                        Write-CHLog -strFunction "Invoke-CHBITSRepair" -strMessage "ERROR - Installation of BITS Service completed, but could not start the service."
                    
                        #Write PFE Status to Registry
                        [string]$dtmDate = Get-Date -format yyyy-MM-dd
                        [string]$dtmTime = Get-Date -format HH:mm:ss

                        Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_BITSStatus" -strData "UnHealthy" -strDataType string
                        Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_LastDate" -strData $dtmDate -strDataType string
                        Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_LastTime" -strData $dtmTime -strDataType string

                        Return $False
                    }
                }

            }
            Else
            {
                Write-CHLog -strFunction "Invoke-CHBITSRepair" -strMessage "BITS Service install failed with error $intResults."
            
                #Write PFE Status to Registry
                [string]$dtmDate = Get-Date -format yyyy-MM-dd
                [string]$dtmTime = Get-Date -format HH:mm:ss

                Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_BITSStatus" -strData "UnHealthy" -strDataType string
                Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_LastDate" -strData $dtmDate -strDataType string
                Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_LastTime" -strData $dtmTime -strDataType string

            Return $False
            }
        }
    }
    Catch
    {
        #Get first line of error only
        [string]$strErrorMsg = ($Error[0].toString()).Split(".")[0]

        #Catch any error and write tolog
        Write-CHLog -strFunction "Invoke-CHBITSRepair" -strMessage "ERROR - $strErrorMsg"

        #Write PFE Status to Registry
        [string]$dtmDate = Get-Date -format yyyy-MM-dd
        [string]$dtmTime = Get-Date -format HH:mm:ss

            Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_BITSStatus" -strData "UnHealthy" -strDataType string
            Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_LastDate" -strData $dtmDate -strDataType string
            Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_LastTime" -strData $dtmTime -strDataType string

        Return $False
    }

}

Function Send-CHHttpDDR()
{
    <#
    .SYNOPSIS
    Uses HTTP to upload the DDR created by the script to a WebService
    
    .DESCRIPTION
     Uses HTTP to upload the DDR created by the script to a WebService.  The server the DDR will be updloaded to will be the one located in HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft PFE Remediation for Configuration Manager\PrimarySiteName.
     Will return a bool value when complete.
    
    .EXAMPLE


    .PARAMETER DDRFile
    String value. Full path to the DDR File.

    .PARAMETER SiteServer
    String value. Name of the Site Server with the installed webservice to upload the DDR file to.


    .DEPENDENT FUNCTIONS
    Write-CHLog
    Get-CHServiceStatus
    Set-CHServiceStatus
    Set-CHRegistryValue

     #>

    PARAM(
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True)][string]$DDRFile,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True)][string]$SiteServer
    )

    #Clear any errors
    $Error.Clear()
  
    If($DDRFile.Substring($DDRFile.Length - 3,3).ToUpper() -eq "DDR"){
        Write-CHLog -strFunction "Send-CHHttpDDR" -strMessage "Received File $DDRFile for http upload."
        Write-CHLog -strFunction "Send-CHHttpDDR" -strMessage "Will check for Primary Site URL Override."    
    
        #Check for Primary Site in Registry and use this value, otherwise use the one passed on commandline
        [string]$strPrimarySiteServer = Get-CHRegistryValue -strRegKey $global:strPFEKeyPath  -strRegValue "PrimarySiteName"

        If(($strPrimarySiteServer -eq "Error") -or ($strPrimarySiteServer -eq "")){
            #Validate Site Server has HTTP:// in it if not add it
            If($SiteServer.Substring(0,7).ToUpper() -ne "HTTP://"){$SiteServer="HTTP://$SiteServer"}
        
            Write-CHLog -strFunction "Send-CHHttpDDR" -strMessage "No override found, will attempt to upload DDR to $SiteServer" 
           
            #Set WebService URL
            [string]$strWebServiceURL = "$SiteServer/PFEIncoming/PFEIncoming.aspx"
        }
        Else{
               
            #Validate Site Server has HTTP:// in it if not add it
            If($strPrimarySiteServer.Substring(0,7).ToUpper() -ne "HTTP://"){$strPrimarySiteServer="HTTP://$strPrimarySiteServer"}
        
            Write-CHLog -strFunction "Send-CHHttpDDR" -strMessage "HTTPUpload(): Override found, switching to upload DDR to $strPrimarySiteServer"

            #Set WebService URL
            [string]$strWebServiceURL = "$strPrimarySiteServer/PFEIncoming/PFEIncoming.aspx"

        }

        #Check to make sure the DDR file is where it should be
        If(Test-Path -Path $DDRFile){
            Try{
                Write-CHLog -strFunction "Send-CHHttpDDR" -strMessage "Sending DDR to webservice" 
                
                #Get the Content of the DDR
                $content = Get-Content -Path "$DDRFile"

                #Create the Web Request                 
                $webRequest = [System.Net.WebRequest]::Create($strWebServiceURL)
                $encodedContent = [System.Text.Encoding]::UTF8.GetBytes($content)
                $webRequest.Method = "POST"

                #encode the message
                if($encodedContent.length -gt 0){
                    $webRequest.ContentLength = $encodedContent.length
                    $requestStream = $webRequest.GetRequestStream()
                    $requestStream.Write($encodedContent, 0, $encodedContent.length)
                    $requestStream.Close()
                }
  
                Write-CHLog -strFunction "Send-CHHttpDDR" -strMessage "DDR was sent to $strWebServiceURL."
                
                #Remove old DDR file
                Remove-Item -Path $DDRFile -Force
                 
                Return $True

            }
            Catch{
                [string]$strErrorMsg = ($Error[0].toString()).Split(".")[0]
                #Catch any error and write tolog
                Write-CHLog -strFunction "Send-CHHttpDDR" -strMessage "ERROR - Failed to upload DDR with error ($strErrorMsg)"

                Return $False
            }
        }
        Else{
            Write-CHLog -strFunction "Send-CHHttpDDR" -strMessage "ERROR - The file $DDRFile is not found."

            Return $False
        }
    }
    Else{
        Write-CHLog -strFunction "Send-CHHttpDDR" -strMessage "WARNING - The file $DDRFile is not a DDR.  Will not upload."

        Return $False
    }
}


#endregion #################################### END FUNCTIONS ####################################>


#region #################################### START GLOBAL VARIABLES ####################################>

[string]$global:strPFEKeyPath = 'HKLM:\software\Microsoft\Microsoft PFE Remediation for Configuration Manager'

#get relative path to script running location
#the full path includes the name of the script; removing it by replacing the name with empty
[string]$global:strCurrentLocation = ($MyInvocation.MyCommand.Path).Replace("\$($MyInvocation.MyCommand.Name)","")

#get client settings from XML file
Try{
    [xml]$xmlUserData = Get-Content "$global:strCurrentLocation\PFERemediationSettings.xml" -ErrorAction Stop
    Write-CHLog "Main.Globals" "XML file found: gathering settings"

    #set user settings from customer indicated settings
    [object]$global:objClientSettings = $xmlUserData.sites.default

    [bool]$global:blnDebug = [System.Convert]::ToBoolean($global:objClientSettings.Debug)
}
Catch{
    Write-CHLog "Main.Globals" "XML file not found: exiting script"
    "Log file location: $strLogFile; exiting script as customer settings XML file is missing"
    
    #code for writing DDR
    
    #exiting with generic exit code; more logic is required for exit code that has meaning
    Exit(2)
}

#get SCCM assigned sitecode and version
Try{
    [string]$global:strSiteCode = Get-CHRegistryValue "HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client" "AssignedSiteCode"
    [string]$strSCCMVersion = Get-CHRegistryValue "HKLM:\software\microsoft\sms\mobile client" "ProductVersion"
}
Catch{
    [string]$global:strSiteCode = $global:objClientSettings.Sitecode
    [string]$strSCCMVersion = "0"
}

if($strSCCMVersion.StartsWith("4")){
    if($global:objClientSettings.RemediateOld2007Client -eq $False){
        Write-CHLog "Main.Globals" "Error - SCCM 2007 is not supported in this script; Update setting RemediateOld2007Client to True to continue; quitting script"
    
        #exiting with generic exit code; more logic is required for exit code that has meaning
        Exit(2)
    }
    else{
        $global:blnSCCMInstalled = $False
    }
}
elseif($strSCCMVersion.StartsWith("5")){
    $global:blnSCCMInstalled = $True
}
else{
    $global:blnSCCMInstalled = $False
}

#get OS Name and Version
[string]$strOSName = Get-CHRegistryValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" "ProductName"
[string]$global:strOSVersion = Get-CHRegistryValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" "CurrentVersion"

#check for OS version greater than 6 (Vista or higher)
if([int](($global:strOSVersion).split(".",2)[0]) -lt 6){
    if([int](($global:strOSVersion).split(".",2)[1]) -eq 0){ #Check for Vista
        #Verify that if the OS is Vista that the PowerShell version is at least 2
        if((get-host).Version.Major -lt 2){
            Write-CHLog "Main.Globals" "The minimum supported PowerShell version for this utility is 2.x; exiting script"
            Exit(3)
        }
    }
    
    Write-CHLog "Main.Globals" "The minimum supported Operating System for this utility is Vista; exiting script"
    Exit(3)
}

#set OS Type using OS Name
if (($strOSName.toLower()).Contains("server")){ [string]$global:strOSType = "server" }
else { [string]$global:strOSType = "workstation" }

#endregion #################################### END GLOBAL VARIABLES ####################################>

#region #################################### START MAIN LOGIC ####################################>

#script needs to run as an administrator; no action will be taken if check for admin is false
if(([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){
    if((Get-Process "tsmanager" -ErrorAction SilentlyContinue) -eq $null){
        
        Write-CHLog -strFunction "Main" -strMessage "Checking log file size"

        #if log file is over 5MB, rename the log
        if((Get-ChildItem "$global:strCurrentLocation\PS-PFERemediationScript.log").Length -gt 5242880){
            Try{
                #remove the old .lo_ file if it exists and rename the large log file
                if(Test-Path "$global:strCurrentLocation\PS-PFERemediationScript.lo_" -ErrorAction SilentlyContinue){ Remove-Item "$global:strCurrentLocation\PS-PFERemediationScript.lo_" -ErrorAction Stop}
                Rename-Item "$global:strCurrentLocation\PS-PFERemediationScript.log" "$global:strCurrentLocation\PS-PFERemediationScript.lo_" -Force -ErrorAction Stop
            }
            Catch{
                Write-CHLog -strFunction "Main" -strMessage "Error - Cannot rename log file"
            }
        }
        
        Write-CHLog -strFunction "Main" -strMessage "PFE Client Remediation Script Started"
        
        [string]$strAgentName = "PFE Remediation"

        Write-CHLog "Main.PreCheck" "Script version is $strScriptVersion"

        #Initiate PFE Reboot Status
        $strPFEReboot = "False"
        
        ###############################################################################
        #   Check Registry Configuration
        ###############################################################################

        if($global:blnDebug) { Write-CHLog "Main.PreCheck" "Checking Microsoft PFE Remediation for Configuration Manager registry configuration" }

        if(!(Test-Path $global:strPFEKeyPath)){
            #PFE registry keys do not exist yet; creating them
            [string]$strRegKey = ($global:strPFEKeyPath).Split("\")[3]
            [string]$strRegPath = $global:strPFEKeyPath.Replace("\$strRegKey","")
            Try{
                New-Item -Path $strRegPath -Name $strRegKey -ErrorAction Stop | Out-Null
            }
            Catch{
                Write-CHLog "Main.PreCheck" "Error: Cannot write registry key Microsoft PFE Remediation for Configuration Manager"
            }
            
            #Set-CHRegistryValue $global:strPFEKeyPath
            
            Set-CHRegistryValue $global:strPFEKeyPath "Agent Site" $global:strSiteCode "string"
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_WMIRebuildAttempts" 0 "dword"
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_RebootPending" $strPFEReboot "string"
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_LastAction" "System Check" "string"
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_LastDate" (Get-Date -format yyyy-MM-dd) "string"
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_LastTime" (Get-Date -format HH:mm:ss) "string"
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_ScriptVer" $strScriptVersion "string"
        }
        else{
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_ScriptVer" $strScriptVersion "string"
            
            if((Get-CHRegistryValue $global:strPFEKeyPath "PFE_WMIRebuildAttempts") -eq ""){
                Set-CHRegistryValue $global:strPFEKeyPath "PFE_WMIRebuildAttempts" 0 "dword"
            }
        }

        if($global:blnDebug) { Write-CHLog "Main.PreCheck" "Registry key configuration completed" }

        <### END REGISTRY CHECK ###>

        ###############################################################################
        #   Check Existing DDR Files
        ###############################################################################

        Write-CHLog "Main.PreCheck" "Looking for existing DDR and deleting file if found"
        
        if(Test-Path "$global:strCurrentLocation\$($env:COMPUTERNAME).ddr"){
            Try{ 
                Remove-Item "$global:strCurrentLocation\$($env:COMPUTERNAME).ddr" -ErrorAction Stop | Out-Null
                if($global:blnDebug) { Write-CHLog "Main.PreCheck" "Old DDR deleted" }
            }
            Catch{
                Write-CHLog "Main.PreCheck" "Error: Failed to delete existing DDR"
            }
        }

        ###############################################################################
        #   Check Pending Reboots
        ###############################################################################

        $strRebootPending = Get-CHRegistryValue $global:strPFEKeyPath "PFE_RebootPending"

        if($strRebootPending -eq $True){
            if($global:blnDebug) { Write-CHLog "Main.RebootCheck" "Checking Reboot Status" }

            [string]$strLastReboot = Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue | foreach { $_.lastbootuptime }
            [datetime]$dtLastReboot = Get-Date -date ([System.Management.ManagementDateTimeconverter]::ToDateTime($strLastReboot)) -Format yyyy-MM-dd HH:mm:ss

            if($global:blnDebug) { Write-CHLog "Main.RebootCheck" "Last Reboot: $dtLastReboot" }

            [string]$strScriptLastRunDate = Get-CHRegistryValue $global:strPFEKeyPath "PFE_LastDate"
            [string]$strScriptLastRunTime = Get-CHRegistryValue $global:strPFEKeyPath "PFE_LastTime"
            [datetime]$dtScriptLastRun = [datetime]"$strScriptLastRunDate $strScriptLastRunTime"

            if($global:blnDebug) { Write-CHLog "Main.RebootCheck" "Last Time Script Ran: $dtLastReboot" }

            if($dtLastReboot -gt $dtScriptLastRun){
                if($global:blnDebug) { Write-CHLog "Main.RebootCheck" "Setting PFE_RebootPending to False" }

                $blnRebootPending = $False
                Set-CHRegistryValue $global:strPFEKeyPath "PFE_RebootPending" $strRebootPending "string"
            }
            else{ $strRebootPending = $True }
        }

        ###############################################################################
        #   Gather System Data
        ###############################################################################

        [string]$strDomain = Get-CHRegistryValue "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters" "Domain"
        if($strDomain -ne ""){
            [string]$strResourceName = "$($env:COMPUTERNAME).$strDomain"
        }
        else{
            [string]$strResourceName = $env:COMPUTERNAME
        }

        #Get AD Site Name
        [string]$strADSite = Get-CHRegistryValue "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters" "DynamicSiteName"

        #Get AD Machine GUID
        [string]$strMachineGUID = Get-CHRegistryValue "HKLM:\Software\Microsoft\Cryptography" "MachineGUID"

        #Get processor architecture from registry
        [string]$strOSArch = Get-CHRegistryValue "HKLM:\System\CurrentControlSet\Control\Session Manager\Environment" "Processor_Architecture"

        #Update script status in registry
        Set-CHRegistryValue $global:strPFEKeyPath "PFE_LastAction" "Gather" "string"
        Set-CHRegistryValue $global:strPFEKeyPath "PFE_LastDate" (Get-Date -format yyyy-MM-dd) "string"
        Set-CHRegistryValue $global:strPFEKeyPath "PFE_LastTime" (Get-Date -format HH:mm:ss) "string"

        ###############################################################################
        #   Check Provisioning Mode
        ###############################################################################

        if($global:blnSCCMInstalled -eq $True){
            [string]$strProvisioningMode = Get-CHRegistryValue -strRegKey HKLM:\SOFTWARE\Microsoft\CCM\CcmExec -strRegValue "ProvisioningMode"
            
            Write-CHLog "Main.Gather" "Check if client is in provisioning mode"

            if ($strProvisioningMode -ne "Error"){
                if ($strProvisioningMode -eq "true" -or $strProvisioningMode -eq ""){
        
                    Write-CHLog "Main" "Client is in provisioning mode"

                    if(($global:objClientSettings.WorkstationRemediation -eq $true -and $global:strOSType -eq "workstation") -or ($global:objClientSettings.ServerRemediation -eq $true -and $global:strOSType -eq "server")){
                       Try{
                            Write-CHLog "Main.Gather" "Setting provisioning mode to false"

                            Invoke-WmiMethod -Namespace "root\ccm" -Class "SMS_Client" -Name "SetClientProvisioningMode" -ArgumentList $false -ErrorAction Stop | Out-Null

                            Write-CHLog "Main.Gather" "Client no longer in provisioning mode"

                            $strProvisioningMode = "false"
						
                        }
                        Catch{
                            Write-CHLog "Main.Gather" "Error invoking SetClientProvisioningMode WMI method"
                        }
                    }
                    else{
                        Write-CHLog "Main.Gather" "Remediation has been disabled for this hardware type. Will not repair provisioning mode."
                    }
                }
                else{
                    if($global:blnDebug) { Write-CHLog "Main.Gather()" "Client is not in provisioning mode" }
                }
            }
            else{
                Write-CHLog "Main.Gather" "Couldn't read ProvisioningMode value from the registry."
            }

            Set-CHRegistryValue $global:strPFEKeyPath -strRegValue "PFE_LastAction" -strData "Check Provisioning Mode" -strDataType "string"
            Set-CHRegistryValue $global:strPFEKeyPath -strRegValue "PFE_ProvisioningMode" -strData $strProvisioningMode.ToUpper() -strDataType "string"
            Set-CHRegistryValue $global:strPFEKeyPath -strRegValue "PFE_LastDate" -strData (Get-Date -format yyyy-MM-dd) -strDataType "string"
            Set-CHRegistryValue $global:strPFEKeyPath -strRegValue "PFE_LastTime" -strData (Get-Date -format HH:mm:ss) -strDataType "string"

        }
        
        ###############################################################################
        #   Check to see if client is an SCCM site server
        ###############################################################################

        if($global:strOSType -eq "server"){
            if((Get-CHRegistryValue "HKLM:\Software\Microsoft\SMS\Components\SMS_EXECUTIVE\Threads\SMS_COMPONENT_MONITOR" "DLL") -eq "Error"){
                if((Get-CHRegistryValue "HKLM:\Software\Microsoft\SMS\Operations Management\SMS Server Role\SMS Distribution Point" "Version") -eq "Error"){
                    [bool]$blnSiteServer = $False
                    if($global:blnDebug) { Write-CHLog "Main.Gather" "Server is not an SCCM Site Server" }
                }
                else{
                    [bool]$blnSiteServer = $True
                    Write-CHLog "Main.Gather" "Server is an SCCM Site Server"
                }
            }
            else{
                [bool]$blnSiteServer = $True

                Write-CHLog "Main.Gather" "Server is an SCCM Site Server; checking to see if the server is a Management Point"
                if((Get-CHRegistryValue "HKLM:\Software\Microsoft\SMS\MP" "MP Hostname") -eq ""){
                    [bool]$blnMP = $False
                    if($global:blnDebug) { Write-CHLog "Main.Gather" "Server is not a Management Point" }
                }
                else{
                    [bool]$blnMP = $True
                    Write-CHLog "Main.Gather()" "Server is a Management Point"
                }
            }
        }
        
        Write-CHLog "Main.Gather" "CCM Assigned Site: $global:strSitecode"
        Write-CHLog "Main.Gather" "Computer Name: $env:COMPUTERNAME"
        Write-CHLog "Main.Gather" "Domain Name: $strDomain"
        Write-CHLog "Main.Gather" "FQDN: $strResourceName"
        Write-CHLog "Main.Gather" "System Type: $global:strOSType"
        Write-CHLog "Main.Gather" "Architecture Type: $strOSArch"
        Write-CHLog "Main.Gather" "Operating System: $strOSName"
         Write-CHLog "Main.Gather" "CCM Assigned Site: $global:strSitecode"

        ###############################################################################
        #   Check Free MB on System Drive
        ###############################################################################
        
        [int]$intSystemDriveMBFree = [int]((Get-PSDrive $($env:SystemDrive)[0]).Free / 1MB)

        if($global:blnDebug){ Write-CHLog -strFunction "Main.Gather" -strMessage "Free space on $env:SystemDrive is $intSystemDriveMBFree MB" }

        if($intSystemDriveMBFree -lt 512){
            Write-CHLog "Main.Gather" "Error - System drive $env:SystemDrive has less than 500MB free space. Script will not attempt to install client"
        }

        Set-CHRegistryValue -strRegKey $global:strPFEKeyPath -strRegValue "PFE_CFreeSpace" -strData $intSystemDriveMBFree -strDataType "string"

        ###############################################################################
        #   Start Services Check
        ###############################################################################

        Write-CHLog "Main.ServicesCheck" "Beginning Service Verification"

        ###############################################################################
        #   Check BITS Service
        ###############################################################################

        if($global:objClientSettings.BITSService -eq $True){
            [string]$strBITSHealth = "Unhealthy"

            if($global:blnDebug){ Write-CHLog "Main.ServicesCheck" "Beginning BITS Service Verification" }

            if(!(Get-CHServiceStatus "BITS" -strStartType NotDisabled -strStatus NotMonitored)){
                if($global:objClientSettings.ServerRemediation -eq $true -and $global:strOSType -eq "server"){
                    if((Set-CHServiceStatus "BITS" -strStartType Manual -strStatus Running) -eq $true){
                        [string]$strBITSHealth = "Healthy"
                    }
                    else{ [string]$strBITSHealth = "Unhealthy" }
                }
                elseif($global:objClientSettings.WorkstationRemediation -eq $true -and $global:strOSType -eq "workstation"){
                    if((Set-CHServiceStatus "BITS" -strStartType DelayedAuto -strStatus Running) -eq $true){
                        [string]$strBITSHealth = "Healthy"
                    }
                    else{ [string]$strBITSHealth = "Unhealthy" }
                }
                else{ if($global:blnDebug){
                    Write-CHLog "Main.ServicesCheck" "Remediation disabled; will not attempt to remediate BITS" }
                    [string]$strBITSHealth = "Unhealthy"
                }
            }
            else{ [string]$strBITSHealth = "Healthy" }

            #Update script status in registry
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_BITSStatus" $strBITSHealth "string"
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_LastAction" "BITS Service" "string"
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_LastDate" (Get-Date -format yyyy-MM-dd) "string"
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_LastTime" (Get-Date -format HH:mm:ss) "string"
        }

        ###############################################################################
        #   Check Windows Update Service
        ###############################################################################

        if($global:objClientSettings.WUAService -eq $True){
            [string]$strWUAHealth = "Unhealthy"

            if($global:blnDebug){ Write-CHLog "Main.ServicesCheck" "Beginning Windows Update Agent Service Verification" }

            if($global:strOSVersion -ne "6.1"){
                if(!(Get-CHServiceStatus "wuauserv" -strStartType Manual -strStatus NotMonitored)){
                    if(($global:objClientSettings.WorkstationRemediation -eq $true -and $global:strOSType -eq "workstation") -or ($global:objClientSettings.ServerRemediation -eq $true -and $global:strOSType -eq "server")){
                        if((Set-CHServiceStatus "wuauserv" -strStartType Manual -strStatus Running) -eq $true){
                            [string]$strWUAHealth = "Healthy"
                        }
                    }
                    else{ if($global:blnDebug){ Write-CHLog "Main.ServicesCheck" "Remediation disabled; will not attempt to remediate Windows Update Agent Service" } }
                }
                else{ [string]$strWUAHealth = "Healthy" }
            }
            else{
                if(!(Get-CHServiceStatus "wuauserv" -strStartType DelayedAuto -strStatus Running)){
                    if(($global:objClientSettings.WorkstationRemediation -eq $true -and $global:strOSType -eq "workstation") -or ($global:objClientSettings.ServerRemediation -eq $true -and $global:strOSType -eq "server")){
                        if((Set-CHServiceStatus "wuauserv" -strStartType DelayedAuto -strStatus Running) -eq $true){
                            [string]$strWUAHealth = "Healthy"
                        }
                    }
                    else{ if($global:blnDebug){ Write-CHLog "Main.ServicesCheck" "Remediation disabled; will not attempt to remediate Windows Update Agent Service" } }
                }
                else{ [string]$strWUAHealth = "Healthy" }
            }

            #Update script status in registry
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_WUAStatus" $strWUAHealth "string"
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_LastAction" "WUA Service" "string"
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_LastDate" (Get-Date -format yyyy-MM-dd) "string"
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_LastTime" (Get-Date -format HH:mm:ss) "string"
        }

        ###############################################################################
        #   Check Windows Management Instrumentation (WMI) Service
        ###############################################################################

        if($global:objClientSettings.WMIService -eq $True){
            [string]$strWMIHealth = "Unhealthy"

            if($global:blnDebug){ Write-CHLog "Main.ServicesCheck" "Beginning WMI Service Verification" }

            if(!(Get-CHServiceStatus "winmgmt" -strStartType Automatic -strStatus Running)){
                if(($global:objClientSettings.WorkstationRemediation -eq $true -and $global:strOSType -eq "workstation") -or ($global:objClientSettings.ServerRemediation -eq $true -and $global:strOSType -eq "server")){
                    if((Set-CHServiceStatus "winmgmt" -strStartType Automatic -strStatus Running) -eq $True){
                        [string]$strWMIHealth = "Healthy"
                    }
                }
                else{ if($global:blnDebug){ Write-CHLog "Main.ServicesCheck" "Remediation disabled; will not attempt to remediate WMI Service" } }
            }
            else{ [string]$strWMIHealth = "Healthy" }

            #Update script status in registry
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_WMIStatus" $strWMIHealth "string"
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_LastAction" "WMI Service" "string"
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_LastDate" (Get-Date -format yyyy-MM-dd) "string"
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_LastTime" (Get-Date -format HH:mm:ss) "string"
        }

        ###############################################################################
        #   Check CCMExec Service
        ###############################################################################

        if($global:objClientSettings.CCMService -eq $True){
            [string]$strCCMHealth = "Unhealthy"

            if($global:blnDebug){ Write-CHLog "Main.ServicesCheck" "Beginning SMS Agent Host Service Verification" }

            if($blnMP){
                if(!(Get-CHServiceStatus "ccmexec" -strStartType Automatic -strStatus Running)){
                    if((get-service ccmexec -ErrorAction SilentlyContinue) -eq $null){
                        Write-CHLog "Main.ServicesCheck" "Warning - SMS Agent Host Service is not installed"
                        [bool]$global:blnSCCMInstalled = $False
                    }
                    else{
                        if(($global:objClientSettings.WorkstationRemediation -eq $true -and $global:strOSType -eq "workstation") -or ($global:objClientSettings.ServerRemediation -eq $true -and $global:strOSType -eq "server")){
                            if((Set-CHServiceStatus "ccmexec" -strStartType Automatic -strStatus Running) -eq $True){
                                [string]$strCCMHealth = "Healthy"
                            }
                        }
                        else{ if($global:blnDebug){ Write-CHLog "Main.ServicesCheck" "Remediation disabled; will not attempt to remediate SMS Agent Host Service" } }
                    }
                }
                else{
                    [string]$strCCMHealth = "Healthy"
                    if($global:blnSCCMInstalled -eq $False){
                        Write-CHLog "Main.ServicesCheck" "Error - Server is an MP and the SMS Agent Host Service is present, but the client is not found; will install client if remediation is enabled"
                        [string]$strCCMHealth = "Unhealthy"
                    }
                }
            }
            else{
                if(!(Get-CHServiceStatus "ccmexec" -strStartType DelayedAuto -strStatus Running)){
                    if((Get-Service ccmexec -ErrorAction SilentlyContinue) -eq $null){
                        Write-CHLog "Main.ServicesCheck" "Warning - SMS Agent Host Service is not installed"
                        [string]$strCCMHealth = "Unhealthy"
                        [bool]$global:blnSCCMInstalled = $False
                    }                    
                    else{
                        if(($global:objClientSettings.WorkstationRemediation -eq $true -and $global:strOSType -eq "workstation") -or ($global:objClientSettings.ServerRemediation -eq $true -and $global:strOSType -eq "server")){
                            if((Set-CHServiceStatus "ccmexec" -strStartType DelayedAuto -strStatus Running) -eq $True){
                                [string]$strCCMHealth = "Healthy"
                            }
                        }
                        else{ if($global:blnDebug){ Write-CHLog "Main.ServicesCheck" "Remediation disabled; will not attempt to remediate SMS Agent Host Service" } }
                    }
                }
                else{ [string]$strCCMHealth = "Healthy" }
            }

            #Update script status in registry
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_CCMStatus" $strCCMHealth "string"
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_LastAction" "SMS Agent Host Service" "string"
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_LastDate" (Get-Date -format yyyy-MM-dd) "string"
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_LastTime" (Get-Date -format HH:mm:ss) "string"
        }

        ###############################################################################
        #   Check Policy Platform Local Authority Service
        ############################################################################### 

        if($global:objClientSettings.PolicyPlatformLocalAuthorityService -eq $True -and $global:blnSCCMInstalled){
            [string]$strPPLAHealth = "Unhealthy"

            if($global:blnDebug){ Write-CHLog "Main.ServicesCheck" "Beginning Policy Platform Local Authority Service Verification" }

            if(!(Get-CHServiceStatus "lpasvc" -strStartType Manual -strStatus NotMonitored)){
                if(($global:objClientSettings.WorkstationRemediation -eq $true -and $global:strOSType -eq "workstation") -or ($global:objClientSettings.ServerRemediation -eq $true -and $global:strOSType -eq "server")){
                    if((Set-CHServiceStatus "lpasvc" -strStartType Manual -strStatus Running) -eq $True){
                        [string]$strPPLAHealth = "Healthy"
                    }
                }
                else{ if($global:blnDebug){ Write-CHLog "Main.ServicesCheck" "Remediation disabled; will not attempt to remediate Policy Platform Local Authority Service" } }
            }
            else{ [string]$strPPLAHealth = "Healthy" }

            #Update script status in registry
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_PolicyPlatformLAStatus" $strPPLAHealth "string"
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_LastAction" "Policy Platform Local Authority Service" "string"
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_LastDate" (Get-Date -format yyyy-MM-dd) "string"
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_LastTime" (Get-Date -format HH:mm:ss) "string"
        }

        ###############################################################################
        #   Check Policy Platform Processor Service
        ###############################################################################

        if($global:objClientSettings.PolicyPlatformLocalAuthorityService -eq $True -and $global:blnSCCMInstalled){
            [string]$strPPPHealth = "Unhealthy"

            if($global:blnDebug){ Write-CHLog "Main.ServicesCheck" "Beginning Policy Platform Processor Service Verification" }

            if(!(Get-CHServiceStatus "lppsvc" -strStartType Manual -strStatus NotMonitored)){
                if(($global:objClientSettings.WorkstationRemediation -eq $true -and $global:strOSType -eq "workstation") -or ($global:objClientSettings.ServerRemediation -eq $true -and $global:strOSType -eq "server")){
                    if((Set-CHServiceStatus "lppsvc" -strStartType Manual -strStatus Running) -eq $True){
                        [string]$strPPPHealth = "Healthy"
                    }
                }
                else{ if($global:blnDebug){ Write-CHLog "Main.ServicesCheck" "Remediation disabled; will not attempt to remediate Policy Platform Processor Service" } }
            }
            else{ [string]$strPPPHealth = "Healthy" }

            #Update script status in registry
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_PolicyPlatformProcessorStatus" $strPPPHealth "string"
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_LastAction" "Policy Platform Processor Service" "string"
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_LastDate" (Get-Date -format yyyy-MM-dd) "string"
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_LastTime" (Get-Date -format HH:mm:ss) "string"
        }

        ###############################################################################
        #   Check Alternate Content Provider Service
        ###############################################################################

        if($global:objClientSettings.ACPService -eq $True){
            [string]$strACPHealth = "Unhealthy"

            if($global:blnDebug){ Write-CHLog "Main.ServicesCheck" "Beginning $($global:objClientSettings.ACPServiceName) Service Verification" }

            if((Get-CHServiceStatus -strServiceName $($global:objClientSettings.ACPServiceName) -strStartType $global:objClientSettings.ACPServiceStartType -strStatus Running) -eq $True){
                if($global:blnDebug){ Write-CHLog "Main.ServicesCheck" "$($global:objClientSettings.ACPServiceName) is Healthy" }
                [string]$strACPHealth = "Healthy"
            }
            else{
                if(($global:objClientSettings.WorkstationRemediation -eq $true -and $global:strOSType -eq "workstation") -or ($global:objClientSettings.ServerRemediation -eq $true -and $global:strOSType -eq "server")){
                    if((Get-Service $($global:objClientSettings.ACPServiceName) -ErrorAction SilentlyContinue) -eq $null){
                        [bool]$blnACPInstall = $True
                    }
                    else{
                        if((Set-CHServiceStatus -strServiceName $($global:objClientSettings.ACPServiceName) -strStartType $global:objClientSettings.ACPServiceStartType -strStatus Running) -eq $True){
                            if($global:blnDebug){ Write-CHLog "Main.ServicesCheck" "$($global:objClientSettings.ACPServiceName) is Healthy" }
                            [string]$strACPHealth = "Healthy"
                        }
                        else{  Write-CHLog "Main.ServicesCheck" "Error - Remediation of $($global:objClientSettings.ACPServiceName) failed" }
                    }
                }
                else{ if($global:blnDebug){ Write-CHLog "Main.ServicesCheck" "Remediation disabled; will not attempt to remediate $($global:objClientSettings.ACPServiceName) Service" } }
            }

            #Update script status in registry
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_ACPStatus" $strACPHealth "string"
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_LastAction" "ACP Service" "string"
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_LastDate" (Get-Date -format yyyy-MM-dd) "string"
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_LastTime" (Get-Date -format HH:mm:ss) "string"
        }

        ###############################################################################
        #   Check WMI Health
        ###############################################################################

        if($global:objClientSettings.WMIReadRepository -eq $True -and $strWMIHealth -eq "Healthy"){
            [string]$strWMIReadRepository = "Healthy"
            [string]$strWMIWriteRepository = "Healthy"

            Write-CHLog "Main.WMIHealth" "Beginning WMI repository verification"

            if(!(Test-CHWMIHealth)){
                Write-CHLog "Main.WMIHealth" "Error - WMI repository verification failed"
                [string]$strWMIReadRepository = "Unhealthy"
                [string]$strWMIWriteRepository = "Unhealthy"
                $blnWMIHealth = $False
            }
            else{
                Write-CHLog "Main.WMIHealth" "WMI repository verification was successful"
                $blnWMIHealth = $True
            }

            #Update script status in registry
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_WMIReadRepository" $strWMIReadRepository "string"
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_WMIWriteRepository" $strWMIWriteRepository "string"
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_LastAction" "WMI Verification" "string"
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_LastDate" (Get-Date -format yyyy-MM-dd) "string"
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_LastTime" (Get-Date -format HH:mm:ss) "string"
        }
        else{
            if($strWMIHealth -ne "Healthy"){
                Write-CHLog "Main.WMIHealth" "Warning - Will not attempt WMI read repository as WMI Service health is unhealthy"
                Write-CHLog "Main.WMIHealth" "Warning - Verify Windows Management Instrumentation Service is set to Automatic and is Running"
            }
            else{
                Write-CHLog "Main.WMIHealth" "Warning - Client Setting WMIReadRepository from XML file is not set to True; no verification performed"
            }
        }

        ###############################################################################
        #   Rebuild WMI
        ###############################################################################

        if($global:objClientSettings.WMIRebuild -eq $True -and ($strWMIReadRepository -eq "Unhealthy" -or $strWMIWriteRepository -eq "Unhealthy") -and $global:strOSType -eq "workstation" -and $strWMIHealth -eq "Healthy" -and $global:objClientSettings.WorkstationRemediation -eq $True){
            Write-CHLog "Main.RebuildWMI" "Beginning WMI rebuild"
            
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_LastAction" "WMI Rebuild" "string"
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_LastDate" (Get-Date -format yyyy-MM-dd) "string"
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_LastTime" (Get-Date -format HH:mm:ss) "string"

            if(Invoke-CHWMIRebuild -eq $True){
                Write-CHLog "Main.RebuildWMI" "WMI Rebuild Successful"
            }
            else{
                Write-CHLog "Main.RebuildWMI" "Error - WMI rebuild failed; will not attempt to reinstall SCCM client"
            }
        }
        elseif($global:objClientSettings.WMIRebuild -eq $False -and ($strWMIReadRepository -eq "Unhealthy" -or $strWMIWriteRepository -eq "Unhealthy") -and $strWMIHealth -eq "Healthy"){
            Write-CHLog "Main.RebuildWMI" "Warning - WMI is unhealthy, however the client Setting WMIRebuild from XML file is not set to True; WMI will not be rebuilt"
        }
        elseif($global:objClientSettings.WMIRebuild -eq $True -and ($strWMIReadRepository -eq "Unhealthy" -or $strWMIWriteRepository -eq "Unhealthy") -and $global:strOSType -eq "workstation" -and $global:objClientSettings.WorkstationRemediation -eq $False){
            Write-CHLog "Main.RebuildWMI" "Warning - WMI is unhealthy, however the client Setting WorkstationRemediation from XML file is not set to True; WMI will not be rebuilt"
        }
        elseif($global:strOSType -eq "server" -and ($strWMIReadRepository -eq "Unhealthy" -or $strWMIWriteRepository -eq "Unhealthy")){
            Write-CHLog "Main.RebuildWMI" "Warning - WMI is unhealthy but the client has a Server Operating System; WMI will not be rebuilt"
        }
        elseif($strWMIHealth -ne "Healthy"){
            Write-CHLog "Main.RebuildWMI" "Warning - Will not attempt to rebuild WMI repository as WMI Service health is unknown or unhealthy"
            Write-CHLog "Main.RebuildWMI" "Warning - Check if client setting WMIService is not set to True; if not True, the service was not checked and overall WMI health was not verified"
            Write-CHLog "Main.RebuildWMI" "Warning - Verify Windows Management Instrumentation Service is set to Automatic and is Running."
        }

        <###############################################################################
        * DCOM Verification and Remediation
        * Checks HKLM:\Software\Microsoft\Ole\EnableDCOM to see if value is Y
        * If not and remediation is enabled, value is set to Y.  Reboot is required for DCOM to be enabled.
        * Script wil not reboot
        * Also checks DCOM Protocols to see if Connection Oriented TCP/IP connection is enabled
        ###############################################################################>

        if($global:objClientSettings.WMIReadRepository -and $global:objClientSettings.DCOMVerify){
            Write-CHLog "Main.DCOMHealth" "Checking DCOM health"

            [string]$strDCOMHealth = "Healthy"
            [string]$strDCOMProtocolHealth = "Healthy"

            [string]$strDCOM = Get-CHRegistryValue "HKLM:\Software\Microsoft\Ole" "EnableDCOM"
            [array]$arrDCOMProtocols = Get-CHRegistryValue "HKLM:\Software\Microsoft\RPC" "DCOM Protocols"

            if($arrDCOMProtocols[0] -eq ""){
                [string]$strDCOMProtocolHealth = "Unhealthy"

                Write-CHLog "Main.DCOMHealth" "Error - DCOM protocols are missing; if remediation is enabled, this will be created"

                if(($global:strOSType -eq "workstation" -and $global:objClientSettings.WorkstationRemediation -eq $True) -or ($global:strOSType -eq "server" -and $global:objClientSettings.ServerRemediation -eq $True)){
                    [string]$strDCOMProtocol = "ncacn_ip_tcp"
                    if((Set-CHRegistryValue "HKLM:\Software\Microsoft\RPC" "DCOM Protocols" -strData $strDCOMProtocol -strDataType multistring) -eq $True){
                        [string]$strDCOMProtocolHealth = "Healthy"
                        [string]$strPFEReboot = "True"
                    }
                    else{
                        [string]$strDCOMProtocolHealth = "Unhealthy"
                    }
                }
                else{ Write-CHLog "Main.DCOMHealth" "Error - DCOM protocols are missing, but remediation is disabled for this hardware type; will not modify DCOM protocols" }
            }
            elseif($arrDCOMProtocols -Contains "ncacn_ip_tcp"){
                if($global:blnDebug){ Write-CHLog "Main" "DCOM Protocols are configured correctly" }
            }
            else{
                Write-CHLog "Main.DCOMHealth" "Error - DCOM Protocols are not configured correctly"

                if(($global:strOSType -eq "workstation" -and $global:objClientSettings.WorkstationRemediation -eq $True) -or ($global:strOSType -eq "server" -and $global:objClientSettings.ServerRemediation -eq $True)){
                    Write-CHLog "Main.DCOMHealth" "DCOM Protocol ncacn_ip_tcp is missing; adding it to the existing list of protocols"

                    [string]$strDCOMProtocols = ""
                    foreach($strDCOMProtocol in $arrDCOMProtocols){
                        if($strDCOMProtocols -eq ""){
                            $strDCOMProtocols = $strDCOMProtocol
                        }
                        else{
                            $strDCOMProtocols = "$strDCOMProtocols,$strDCOMProtocol"
                        }
                    }
                    $strDCOMProtocols = "$strDCOMProtocols,ncacn_ip_tcp"
                    if((Set-CHRegistryValue "HKLM:\Software\Microsoft\RPC" "DCOM Protocols" -strData $strDCOMProtocols -strDataType multistring) -eq $True){
                        [string]$strDCOMProtocolHealth = "Healthy"
                        [string]$strPFEReboot = "True"
                    }
                    else{
                        [string]$strDCOMProtocolHealth = "Unhealthy"
                    }
                }
                else{ Write-CHLog "Main.DCOMHealth" "Error - DCOM protocols are missing, but remediation is disabled for this hardware type; will not modify DCOM protocols" }
            }

            if($strDCOM -ne "Y"){
                [string]$strDCOMHealth = "Unhealthy"
                Write-CHLog "Main.DCOMHealth" "Error - DCOM is not enabled; if remediation is enabled, it will be enabled"

                if(($global:strOSType -eq "workstation" -and $global:objClientSettings.WorkstationRemediation -eq $True) -or ($global:strOSType -eq "server" -and $global:objClientSettings.ServerRemediation -eq $True)){
                    [string]$strDCOMProtocols = "ncacn_ip_tcp"
                    if((Set-CHRegistryValue "HKLM:\Software\Microsoft\Ole" "EnableDCOM" -strData "Y" -strDataType string) -eq $True){
                        [string]$strDCOMHealth = "Healthy"
                        [string]$strPFEReboot = "True"
                    }
                    else{
                        [string]$strDCOMHealth = "Unhealthy"
                    }
                }
                else{ Write-CHLog "Main.DCOMHealth" "Error - DCOM is not enabled, but remediation is disabled for this hardware type; will not enable DCOM" }
            }
            else { if($global:blnDebug){ Write-CHLog "Main.DCOMHealth" "DCOM is enabled" } }

            #Update script status in registry
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_DCOM" $strDCOMHealth "string"
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_DCOMProtocols" $strDCOMProtocolHealth "string"
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_LastAction" "DCOM" "string"
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_PFERebootPending" $strPFEReboot "string"
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_LastDate" (Get-Date -format yyyy-MM-dd) "string"
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_LastTime" (Get-Date -format HH:mm:ss) "string"
        }

        ###############################################################################
        #   Check Stale Logs
        ###############################################################################

        if($global:blnSCCMInstalled -eq $True){
            [array]$arrLogFiles = @("PolicyEvaluator","InventoryAgent")

            Write-CHLog "Main.StaleLogs" "Checking if log files are stale"

            [string]$strStaleLogFiles = ""
            [bool]$blnSCCMClientRepair = $False

            foreach($strSCCMLogFile in $arrLogFiles){
                if((Test-CHStaleLog -strLogFileName $strSCCMLogFile -intDaysStale $global:objClientSettings.LogDaysStale) -eq $True){
                    if($strStaleLogFiles -eq ""){
                        $strStaleLogFiles = $strSCCMLogFile
                    }
                    else{
                        $strStaleLogFiles = "$strStaleLogFiles,$strSCCMLogFile"
                    }
                    [bool]$blnSCCMClientRepair = $True
                }
            }

            if($strStaleLogFiles -eq ""){ $strStaleLogFiles = "Healthy" }
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_PFEStaleLogs" $strStaleLogFiles "string"
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_LastDate" (Get-Date -format yyyy-MM-dd) "string"
            Set-CHRegistryValue $global:strPFEKeyPath "PFE_LastTime" (Get-Date -format HH:mm:ss) "string"
        }

        ###############################################################################
        #   Collect Inventory
        ###############################################################################

        if($global:blnSCCMInstalled -eq $True){
            Write-CHLog "Main.CollectInventory" "Start Collecting Inventory"
            
            #Create empty array to hold inventory types for action
            $InventoryAction = @()
            
            if (($global:objClientSettings.HWINV) -eq $true) { $InventoryAction += ,("PFE_HWINVDate (UTC)",'InventoryActionID = "{00000000-0000-0000-0000-000000000001}"',"Error collecting hardware data from WMI") }
            if (($global:objClientSettings.SWINV) -eq $true) { $InventoryAction += ,("PFE_SWINVDate (UTC)",'InventoryActionID = "{00000000-0000-0000-0000-000000000002}"',"Error collecting software data from WMI") }
            if (($global:objClientSettings.Heartbeat) -eq $true) { $InventoryAction += ,("PFE_HeartbeatDate (UTC)",'InventoryActionID = "{00000000-0000-0000-0000-000000000003}"',"Error collecting heartbeat data from WMI") }
            
            foreach ($Action in $InventoryAction){
                Try{
                    $arrInv = Get-WmiObject -Class InventoryActionStatus -Namespace "root\ccm\invagt" -Filter $Action[1] -ErrorAction Stop
                    if ($arrInv.GetType()){
                        foreach ($objInv in $arrInv){
                            [datetime]$dtmInvDate = Get-Date -Date ([System.Management.ManagementDateTimeconverter]::ToDateTime($objInv.LastReportDate)) -Format 'yyyy-MM-dd HH:mm:ss'
                            [string]$dtmInvDateUTC = ("{0:yyyy-MM-dd HH:mm:ss}" -f $dtmInvDate.ToUniversalTime())
                            Set-CHRegistryValue $global:strPFEKeyPath -strRegValue $Action[0] -strData $dtmInvDateUTC -strDataType "string"
                        }
                    }
                }
                Catch{
                    Write-CHLog "Main.CollectInventory" $Action[2]
                }
            }

            #update status in registry
            Set-CHRegistryValue $global:strPFEKeyPath -strRegValue "PFE_LastAction" -strData "Collect Inventory Dates" -strDataType "string"
            Set-CHRegistryValue $global:strPFEKeyPath -strRegValue "PFE_LastDate" -strData (Get-Date -format yyyy-MM-dd) -strDataType "string"
            Set-CHRegistryValue $global:strPFEKeyPath -strRegValue "PFE_LastTime" -strData (Get-Date -format HH:mm:ss) -strDataType "string"
        }

        ###############################################################################
        #   Check Lantern Application CI
        ###############################################################################

        if($global:blnSCCMInstalled -eq $True -and $global:objClientSettings.LanternAppCI -eq $True){
            Write-CHLog "Main.CheckLantern" "Checking Application Deployment Policy matches Application CI"

            if(!(Test-CHLantern)){
                [string]$strLanternAppCI = "Unhealthy"
                $blnSCCMClientRepair = $True
            }
            else{
                [string]$strLanternAppCI = "Healthy"
            }

            Set-CHRegistryValue $global:strPFEKeyPath -strRegValue "PFE_LanternAppCI" -strData $strLanternAppCI -strDataType "string"
            Set-CHRegistryValue $global:strPFEKeyPath -strRegValue "PFE_LastAction" -strData "Lantern Application Test" -strDataType "string"
            Set-CHRegistryValue $global:strPFEKeyPath -strRegValue "PFE_LastDate" -strData (Get-Date -format yyyy-MM-dd) -strDataType "string"
            Set-CHRegistryValue $global:strPFEKeyPath -strRegValue "PFE_LastTime" -strData (Get-Date -format HH:mm:ss) -strDataType "string"
        }

        ###############################################################################
        #   Install Client
        ###############################################################################

        if($blnSCCMClientRepair){ Invoke-CHClientAction -strAction Repair }
        else{
            #get the number of free MB on drive system drive
            [int]$intDriveCFreeMB = Get-CHRegistryValue $global:strPFEKeyPath -strRegValue "PFE_CFreeSpace"
            
            if(($global:blnSCCMInstalled -eq $false) -and $intDriveCFreeMB -ge 512 -and $blnWMIHealth -eq $true){
                Invoke-CHClientAction -strAction Install
            }
            elseif($blnCHWMIHealth -eq $false){
                Write-CHLog -strFunction "Main.InstallClient" -strMessage "Warning - Client will not be installed due to WMI being unhealthy"
            }
            elseif($intDriveCFreeMB -le 512){
                Write-CHLog -strFunction "Main.InstallClient" -strMessage "Error - Client will not be installed due drive space requirements"
            }
            else{
                Write-CHLog -strFunction "Main.InstallClient" -strMessage "Client is already installed"
            }
        }

        if($global:objClientSettings.ACPService -eq $True -and $blnACPInstall){
            Invoke-CHACPInstall -ACPSetup $global:objClientSettings.ACPInstallCmd -ACPServiceName $global:objClientSettings.ACPServiceName -ACPArguments $global:objClientSettings.ACPInstallArgs
        }

        if($global:blnSCCMInstalled){
            [string]$strSCCMGUID = Get-CHini -strFile "c:\windows\smscfg.ini" -strSection "Configuration - Client Properties" -strKey "SMS Unique Identifier"
        }

        ###############################################################################
        #   Update ConfigMgr Client Remediation Registry
        ###############################################################################

        if($strADSite -ne "") { Set-CHRegistryValue $global:strPFEKeyPath -strRegValue "AD Site Name" -strData $strADSite -strDataType "string" }
        else{ Set-CHRegistryValue $global:strPFEKeyPath -strRegValue "AD Site Name" -strData "NO AD SITE ASSIGNED" -strDataType "string" }
        Set-CHRegistryValue $global:strPFEKeyPath -strRegValue "Agent Name" -strData $strAgentName -strDataType "string"
        Set-CHRegistryValue $global:strPFEKeyPath -strRegValue "Agent Site" -strData $global:strSiteCode -strDataType "string"
        Set-CHRegistryValue $global:strPFEKeyPath -strRegValue "Netbios Name" -strData ($env:COMPUTERNAME) -strDataType "string"
        Set-CHRegistryValue $global:strPFEKeyPath -strRegValue "SMS Unique Identifier" -strData $strSCCMGUID -strDataType "string"
        Set-CHRegistryValue $global:strPFEKeyPath -strRegValue "PFE_LastAction" -strData "Update Registry" -strDataType "string"
        Set-CHRegistryValue $global:strPFEKeyPath -strRegValue "PFE_LastDate" -strData (Get-Date -format yyyy-MM-dd) -strDataType "string"
        Set-CHRegistryValue $global:strPFEKeyPath -strRegValue "PFE_LastTime" -strData (Get-Date -format HH:mm:ss) -strDataType "string"

        ###############################################################################
        #   Write ConfigMgr Client Remediation DDR
        ###############################################################################

        if($global:objClientSettings.CreateDDR -eq $True){
            Write-CHLog -strFunction "Main.WriteDDR" -strMessage "Beginning creation of DDR to report remediation status"

            Set-CHRegistryValue $global:strPFEKeyPath -strRegValue "PFE_LastAction" -strData "Create DDR" -strDataType "string"
            Set-CHRegistryValue $global:strPFEKeyPath -strRegValue "PFE_LastDate" -strData (Get-Date -format yyyy-MM-dd) -strDataType "string"
            Set-CHRegistryValue $global:strPFEKeyPath -strRegValue "PFE_LastTime" -strData (Get-Date -format HH:mm:ss) -strDataType "string"

            if(Test-Path "$global:strCurrentLocation\smsrsgenctl.dll"){
                if($global:blnDebug) { Write-CHLog -strFunction "Main.WriteDDR" -strMessage "Registering smsrsgenctl.dll" }
                
                [int]$intRegister = (Start-Process -FilePath "$env:windir\system32\regsvr32.exe" -ArgumentList "/s ""$global:strCurrentLocation\smsrsgenctl.dll""" -WindowStyle Hidden -PassThru -Wait).ExitCode
                
                #Give three seconds to process
                Start-Sleep -Seconds 3

                if($intRegister -ne 0){
                    Write-CHLog -strFunction "Main.WriteDDR" -strMessage "Error - failed to register smsrsgenctl.dll"
                    Write-CHLog -strFunction "Main.WriteDDR" -strMessage "Warning - unable to generate post verification DDR - $intRegister"
                }
                else{
                    if($global:blnDebug) { Write-CHLog -strFunction "Main.WriteDDR" -strMessage "Successfully registered smsrsgenctl.dll" }

                    Try{
                        [object]$objDDR = New-Object -ComObject "SMSResGen.SMSResGen.1"

                        if($global:blnDebug) { Write-CHLog -strFunction "Main.WriteDDR" -strMessage "Successfully created new SMSResGen (DDR) object" }

                        #Variables required when generating DDR
                        [int]$intADDPROP_NONE = 0x0 # &H0 in hexadecimal
                        [int]$intADDPROP_FULL_REPLACE = 0x1 # &H1 in hexadecimal
                        [int]$intADDPROP_GUID = 0x2 # &H2 in hexadecimal
                        [int]$intADDPROP_KEY = 0x8 # &H8 in hexadecimal
                        [int]$intADDPROP_ARRAY = 0x10 # &H10 in hexadecimal
                        [int]$intADDPROP_ARRAY_REPLACE_KEY = 0x19 # &H19 in hexadecimal

                        $objDDR.DDRNew("System",$strAgentName,$global:strSiteCode)

                        if($strSCCMGUID){
                            $objDDR.DDRAddString("SMS Unique Identifier",$strSCCMGUID,64,$intADDPROP_NONE)
                        }
                        else{
                            $objDDR.DDRAddStringArray("Resource Names",@("$strResourceName"),64,$intADDPROP_FULL_REPLACE -or $intADDPROP_KEY -or $intADDPROP_ARRAY)
                        }

                        $objDDR.DDRAddString("NetBIOS Name", $env:COMPUTERNAME, 64, $intADDPROP_NONE)
					    $objDDR.DDRAddString("AD Site Name", $strADSite, 64, $intADDPROP_NONE)
					    $objDDR.DDRAddString("PFE_ScriptVer", $strScriptVersion, 64, $intADDPROP_NONE)
					    $objDDR.DDRAddString("PFE_LastAction", (Get-CHRegistryValue $global:strPFEKeyPath "PFE_LastAction"), 256, $intADDPROP_NONE)
					    $objDDR.DDRAddString("PFE_LastDate", (Get-Date -format yyyy-MM-dd), 64, $intADDPROP_NONE)
					    $objDDR.DDRAddString("PFE_LastTime", (Get-Date -format HH:mm:ss), 64, $intADDPROP_NONE)
					    $objDDR.DDRAddString("PFE_BITSStatus", $strBITSHealth, 64, $intADDPROP_NONE)
					    $objDDR.DDRAddString("PFE_WUAStatus", $strWUAHealth, 64, $intADDPROP_NONE)
					    $objDDR.DDRAddString("PFE_WMIStatus", $strWMIHealth, 64, $intADDPROP_NONE)
					    $objDDR.DDRAddString("PFE_CCMStatus", $strCCMHealth, 64, $intADDPROP_NONE)
					    $objDDR.DDRAddString("PFE_WMIReadRepository", $strWMIReadRepository, 64, $intADDPROP_NONE)
					    $objDDR.DDRAddString("PFE_WMIWriteRepository", $strWMIWriteRepository, 64, $intADDPROP_NONE)
					    $objDDR.DDRAddString("PFE_DCOM", $strDCOMHealth, 64, $intADDPROP_NONE)
					    $objDDR.DDRAddString("PFE_DCOMProtocols", $strDCOMProtocolHealth, 64, $intADDPROP_NONE)
					    $objDDR.DDRAddString("PFE_RebootPending", $strPFEReboot, 64, $intADDPROP_NONE)
					    $objDDR.DDRAddInteger("PFE_CFreeSpace", $intSystemDriveMBFree, $intADDPROP_NONE)
					    $objDDR.DDRAddString("PFE_StaleLogs", $strStaleLogFiles, 64, $intADDPROP_NONE)
					    $objDDR.DDRAddInteger("PFE_WMIRebuildAttempts", (Get-CHRegistryValue $global:strPFEKeyPath "PFE_WMIRebuildAttempts"), $intADDPROP_NONE)
					    $objDDR.DDRAddString("PFE_PolicyPlatformLAStatus", $strPPLAHealth, 64, $intADDPROP_NONE)
					    $objDDR.DDRAddString("PFE_PolicyPlatformProcessorStatus", $strPPPHealth, 64, $intADDPROP_NONE)
					    $objDDR.DDRAddString("PFE_ACPStatus", $strACPHealth, 64, $intADDPROP_NONE)
					    $objDDR.DDRAddString("PFE_LanternAppCI", $strLanternAppCI, 64, $intADDPROP_NONE)
					    if (($global:objClientSettings.HWINV) -eq $true) { $objDDR.DDRAddString("PFE_HardwareInventoryDate (UTC)", (Get-CHRegistryValue $global:strPFEKeyPath "PFE_HWINVDate (UTC)"), 64, $intADDPROP_NONE) }
					    if (($global:objClientSettings.SWINV) -eq $true) { $objDDR.DDRAddString("PFE_SoftwareInventoryDate (UTC)", (Get-CHRegistryValue $global:strPFEKeyPath "PFE_SWINVDate (UTC)"), 64, $intADDPROP_NONE) }
					    if (($global:objClientSettings.Heartbeat) -eq $true) { $objDDR.DDRAddString("PFE_HeartbeatDate (UTC)", (Get-CHRegistryValue $global:strPFEKeyPath "PFE_HeartbeatDate (UTC)"), 64, $intADDPROP_NONE) }
					    $objDDR.DDRAddString("PFE_ProvisioningMode", $strProvisioningMode, 64, $intADDPROP_NONE)

                        $objDDR.DDRWrite("$global:strCurrentLocation\$($env:COMPUTERNAME).DDR")
                        
                        #Check for service stopped or not installed; copy to share or HTTP upload of true
                        Try{
                            [object]$objPFEService = Get-Service PFERemediation -ErrorAction Stop
                            if($objPFEService.Status -ne "Running" -or $intRegister -eq 0){
                                [bool]$blnUpload = $True
                            }
                            else{
                                [bool]$blnUpload = $False
                            }
                        }
                        Catch{
                            #if no service, copy file to network share
                            [bool]$blnUpload = $True
                        }

                        if($blnUpload){
                            
                            if($global:objClientSettings.HTTPDDR -eq $True){
                                
                                if($global:blnDebug) { Write-CHLog -strFunction "Main" -strMessage "Sending the DDR via HTTP Service" }
                                Send-CHHttpDDR -DDRFile "$global:strCurrentLocation\$($env:COMPUTERNAME).DDR" -SiteServer $global:objClientSettings.PrimarySiteURL | out-null
                            }
                            else{
                                if($global:blnDebug) { Write-CHLog -strFunction "Main" -strMessage "Copying DDR to Network Share; validating share path exists" }
                                if(Test-Path "\\$($global:objClientSettings.primarySiteServer)\PFEIncoming$"){
                                    if($global:blnDebug) { Write-CHLog -strFunction "Main" -strMessage "Share path \\$($global:objClientSettings.primarySiteServer)\PFEIncoming$ exists; copying DDR to Network Share" }

                                    Try{
                                        Copy-Item "$global:strCurrentLocation\$($env:COMPUTERNAME).DDR" "\\$($global:objClientSettings.primarySiteServer)\PFEIncoming$" -ErrorAction Stop

                                        if($global:blnDebug) { Write-CHLog -strFunction "Main" -strMessage "Successfully copied DDR to network share" }
                                    }
                                    Catch{
                                        [string]$strErrorMsg = ($Error[0].toString()).Split(".")[0]
                                        Write-CHLog -strFunction "Main" -strMessage "Error - Copy to \\$($global:objClientSettings.primarySiteServer)\PFEIncoming$ failed with error $strErrorMsg"
                                    }
                                }
                                else{
                                    Write-CHLog -strFunction "Main" -strMessage "Error - PFEIncoming$ share is not accessible on $($global:objClientSettings.primarySiteServer)"
                                }
                            }
                        }
                        else{ if($global:blnDebug) { Write-CHLog -strFunction "Main" -strMessage "Not copying DDR as PFE Service will perform this action on next cycle" } }
                    }
                    Catch{
                        #capture error message and log
                        [string]$strErrorMsg = ($Error[0].toString()).Split(".")[0]
                        Write-CHLog -strFunction "Main" -strMessage "Error - failed to create SMSResGen object: $strErrorMsg"
                    }
                 }
            }
            else{ Write-CHLog -strFunction "Main.WriteDDR" "$global:strCurrentLocation\smsrsgenctl.dll does not exist; cannot write DDR" }
        }
    }
    else{
        Write-CHLog "Main" "NO ACTION TAKEN: The Task Sequence Manager is running; not continuing to remediate SCCM client."
    }
}
else{
    Write-CHLog "Main" "NO ACTION TAKEN: The script is not running as an administrator"
}

Write-CHLog -strFunction "Main" -strMessage "PFE Client Remediation Script Completed"

#endregion #################################### END MAIN LOGIC ####################################>