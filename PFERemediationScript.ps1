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
# including attorneys fees, that arise or result from the use or 
# distribution of the Sample Code.
#
# ================================================================== 

#Current Version information for script
[string]$strScriptBuild = "201910151207"
[string]$ScriptVersion = '18.1.5' + "." + $strScriptBuild

# generate threadID for logging
$script:threadId = Get-Random -Minimum 1000 -Maximum 4095

#region #################################### START FUNCTIONS ####################################>

Function Write-CHLog ()
{
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
    [string]$Function,

    [Parameter(Mandatory=$True,
    ValueFromPipelineByPropertyName=$True)]
    [string]$Message
  )
    
  <#
      $Function = "Main"
      $Message = "Test Write-CHLog"
  #>

  #set log file location
  [string]$LogFile = ('{0}\PS-PFERemediationScript.log' -f $script:CurrentLocation)

  #define output to log file    
  #create cmtrace log string
  $toLog = ("{0} `$$<{1}><{2} {3}><thread={4}>" -f ($message), ('PFECH:' +$Function), (Get-Date -Format 'MM-dd-yyyy'), (Get-Date -Format 'HH:mm:ss.ffffff'), ($script:threadId))
 
  #append the output to the file; this will create the file if necessary as well
        
  Try
  {
    $toLog | Out-File -Append -Encoding UTF8 -FilePath $LogFile
  }
  Catch
    {
        'Cannot write to log file; exiting script'
        Exit(1)
    }
}

Function Get-CHRegistryValue ()
{
    <#
    .SYNOPSIS
    Read Registry Value

    .DESCRIPTION
    Accepts string values for registry key and registry value requested

    .EXAMPLE
    Get-CHRegistryValue -RegKey $PFEKeyPath -RegValue "ScriptLog"

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
        [string]$RegKey,

        [Parameter(Mandatory=$True,
        ValueFromPipelineByPropertyName=$True)]
        [string]$RegValue
    )
    
    if($script:Debug ){ Write-CHLog -Function 'Get-CHRegistryValue' -Message ('Getting registry value for {0}\{1}' -f $RegKey, $RegValue) }
    
    Try
    {
        $RegRead = Get-Item -Path $RegKey -ErrorAction Stop | ForEach-Object { $_.GetValue($RegValue) }
        if ($RegRead -eq $null)
        {
            $RegRead = ''
            If($script:Debug ){ Write-CHLog -Function 'Get-CHRegistryValue' -Message ('Warning: The value for {0}\{1} is empty' -f $RegKey, $RegValue) }
        }
    }
    Catch
    {
        $RegRead = 'Error'
        $ErrorMsg = ($Error[0].toString()).Split('.')[0]
        
        Write-CHLog -Function 'Get-CHRegistryValue' -Message ('Failed to get {0} as the path {1} does not exist' -f $RegValue, $RegKey)
        Write-CHLog -Function 'Get-CHRegistryValue' -Message ('Return error: {0}' -f $ErrorMsg)
    }

    #returning status
    if($script:Debug ){Write-CHLog -Function 'Get-CHRegistryValue' -Message ('Return value is {0}' -f $RegRead)}
    return $RegRead
}

Function Set-CHRegistryValue ()
{
    <#
    .SYNOPSIS
    Write Registry Value

    .DESCRIPTION
    Accepts string values for registry key and registry value to include data and data type to write

    .EXAMPLE
    Set-CHRegistryValue -RegKey "HKLM:\SOFTWARE\Microsoft\Microsoft PFE Remediation for Configuration Manager" -RegValue "Test Set Reg Value" -Data "Worked again"

    .EXAMPLE
    Set-CHRegistryValue "HKLM:\SOFTWARE\Microsoft\Microsoft PFE Remediation for Configuration Manage" -RegValue "Test New Reg Value" -Data "Worked" -DataType "string"

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
        [string]$RegKey,

        [Parameter(Mandatory=$True,
        ValueFromPipelineByPropertyName=$True)]
        [string]$RegValue,

        [Parameter(Mandatory=$True,
        ValueFromPipelineByPropertyName=$True)]
        [string]$Data,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [ValidateSet('dword','string','qword','expandstring','binary','multistring')]
        [string]$DataType
    )
    
    if($DataType -ne 'multistring')
    {
        [string]$RegKeyExists = Get-CHRegistryValue -RegKey $RegKey -RegValue $RegValue

        #for cases where new registry values are written, new-itemproperty will set the type
        if ($RegKeyExists -eq 'Error')
        {
            #logging
            if($script:Debug ){ Write-CHLog -Function 'Set-CHRegistryValue' -Message ('Setting new registry value for {0}\{1} to {2}' -f $RegKey, $RegValue, $Data) }
        
            Try
            {
                $null = New-ItemProperty -Path $RegKey -Name $RegValue -Value $Data -PropertyType $DataType -ErrorAction Stop
                if($script:Debug ){ Write-CHLog -Function 'Set-CHRegistryValue' -Message ('New registry value {0}\{1} was created; the value was set to {2}' -f $RegKey, $RegValue, $Data) }
            }
            Catch
            {
                $ErrorMsg = ($Error[0].toString()).Split('.')[0]
                Write-CHLog -Function 'Set-CHRegistryValue' -Message ('New registry value {0}\{1} was not created; the error is {2}' -f $RegKey, $RegValue, $ErrorMsg)
            }
        }
        else
        {
            #logging
            if($script:Debug ){ Write-CHLog -Function 'Set-CHRegistryValue' -Message ('Setting registry value for {0}\{1} to {2}' -f $RegKey, $RegValue, $Data) }

            #most cases are updating existing registry entries
            Try
            {
                Set-ItemProperty -Path $RegKey -Name $RegValue -Value $Data -ErrorAction Stop
                if($script:Debug ){ Write-CHLog -Function 'Set-CHRegistryValue' -Message ('Registry value {0}\{1} was set to {2}' -f $RegKey, $RegValue, $Data) }
            }
            Catch
            {
                $ErrorMsg = ($Error[0].toString()).Split('.')[0]
                Write-CHLog -Function 'Set-CHRegistryValue' -Message ('New registry value {0}\{1} was not created; the error is {2}' -f $RegKey, $RegValue, $ErrorMsg)
            }
        }
    }
    else
    {
        [array]$RegKeyExists = Get-CHRegistryValue -RegKey $RegKey -RegValue $RegValue

        if($script:Debug ){ Write-CHLog -Function 'Set-CHRegistryValue' -Message 'Registry data type is multistring' }

        #for cases where new registry values are written, new-itemproperty will set the type
        if ($RegKeyExists[0] -eq 'Error')
        {
            #logging
            if($script:Debug ){ Write-CHLog -Function 'Set-CHRegistryValue' -Message ('Setting new registry value for {0}\{1} to {2}' -f $RegKey, $RegValue, $Data) }

            #convert strData to array
            [array]$Data = $Data.Split(',')
        
            Try
            {
                $null = New-ItemProperty -Path $RegKey -Name $RegValue -Value $Data -PropertyType $DataType -ErrorAction Stop
                if($script:Debug ){ Write-CHLog -Function 'Set-CHRegistryValue' -Message ('New registry value {0}\{1} was created; the value was set to {2}' -f $RegKey, $RegValue, $Data) }
            }
            Catch
            {
                $ErrorMsg = ($Error[0].toString()).Split('.')[0]
                Write-CHLog -Function 'Set-CHRegistryValue' -Message ('New registry value {0}\{1} was not created; the error is {2}' -f $RegKey, $RegValue, $ErrorMsg)
            }
        }
        else
        {
            #logging
            if($script:Debug ){ Write-CHLog -Function 'Set-CHRegistryValue' -Message ('Setting registry value for {0}\{1} to {2}' -f $RegKey, $RegValue, $Data) }

            #convert strData to array
            [array]$Data = $Data.Split(',')

            #most cases are updating existing registry entries
            Try
            {
                Set-ItemProperty -Path $RegKey -Name $RegValue -Value $Data -ErrorAction Stop
                if($script:Debug ){ Write-CHLog -Function 'Set-CHRegistryValue' -Message ('Registry value {0}\{1} was set to {2}' -f $RegKey, $RegValue, $Data) }
            }
            Catch
            {
                $ErrorMsg = ($Error[0].toString()).Split('.')[0]
                Write-CHLog -Function 'Set-CHRegistryValue' -Message ('New registry value {0}\{1} was not created; the error is {2}' -f $RegKey, $RegValue, $ErrorMsg)
            }
        }
    }
}

Function Test-CHWriteWMI ()
{
    <#
    .SYNOPSIS
    Checks the ability to write to WMI
    .DESCRIPTION
    Attempts to write test objects to WMI namespace and returns boolean value
    .EXAMPLE
    Test-CHWriteWMI -Namespace "root"
    .EXAMPLE
    Test-CHWriteWMI "root\ccm"
    .PARAMETER strNamespace
    String value for the namespace requested for reading
    #>
    param
    (
        [Parameter(Mandatory=$True,
        ValueFromPipelineByPropertyName=$True)]
        [string]$Namespace
    )
 
    <#Test settings to run without function call
	$Namespace = "root\ccm"
	#>
    If($script:Debug ){ Write-CHLog -Function 'Test-CHWriteWMI' -Message ('Attempting to write to {0}' -f $Namespace) }

    #check for prior existence of PFE class in $Namespace
    if ((Get-WmiObject -namespace $Namespace -Class 'PFE' -ErrorAction SilentlyContinue) -ne $null)
    {
        If($script:Debug ){ Write-CHLog -Function 'Test-CHWriteWMI' -Message ('The test class PFE already existed in Namespace {0}; cleaning up created class' -f $Namespace) }
        Try
        {
            #Delete test class from namespace prior to testing
            If($script:Debug ){ Write-CHLog -Function 'Test-CHWriteWMI' -Message ('Namespace {0} can be written to; cleaning up created class' -f $Namespace) }
            [wmiclass]$OldClass = Get-WmiObject -namespace $Namespace -Class 'PFE'
            $OldClass.Delete()
        }
        Catch
        {
            Write-CHLog -Function 'Test-CHWriteWMI' -Message ('Failed to delete test class PFE from {0}' -f $Namespace)
            return $False
        }
    }
            
    Try
    {
        #attempt creation of new class object in namespace
        [wmiclass]$WMIClass = New-Object -TypeName System.Management.ManagementClass -ArgumentList ($Namespace,$null,$null)
        $WMIClass.Name = 'PFE'
        $null = $WMIClass.Put()

        Try
        {
            #add a property to the class called TestProperty and give it a value of TestValue
            $WMIClass.Properties.Add('TestProperty','')
            $WMIClass.SetPropertyValue('TestProperty','TestValue')
            $null = $WMIClass.Put()

            Try
            {
                #create a new instance of the PFE class and changing the value of the TestProperty in this instance
                $NewWMIInstance = $WMIClass.CreateInstance()
                $NewWMIInstance.TestProperty = 'New Instance'

                Try
                {
                    #Cleanup test class in the namespace and returning True for success
                    If($script:Debug ){ Write-CHLog -Function 'Test-CHWriteWMI' -Message ('Namespace {0} can be written to; cleaning up created class' -f $Namespace) }
                    $WMIClass.Delete()
                    return $True
                }
                Catch
                {
                    Write-CHLog -Function 'Test-CHWriteWMI' -Message ('Failed to delete test class PFE from {0}' -f $Namespace)
                    return false
                }
            }
            Catch
            {
                Write-CHLog -Function 'Test-CHWriteWMI' -Message ('Failed to create instance of class PFE to {0}' -f $Namespace)
                return $false
            }
        }
        Catch
        {
            Write-CHLog -Function 'Test-CHWriteWMI' -Message ('Failed to write property TestProperty to PFE class of namespace {0}' -f $Namespace)
            return $false
        }
    }
    Catch
    {
        Write-CHLog -Function 'Test-CHWriteWMI' -Message ('Failed to write class PFE to {0}' -f $Namespace)
        return $false
    }
}

Function Test-CHWMIHealth ()
{
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
    
    Write-CHLog -Function 'Test-CHWMIHealth' -Message 'Running winmgmt /verifyrepository'

    #attempt to verify WMI repository
    $null = & "$env:windir\system32\wbem\winmgmt.exe" /verifyrepository
    if($lastexitcode -ne 0){
        Write-CHLog  -Function 'Test-CHWMIHealth' -Message 'Result of WMI repository check is not consistent'
        return $False
    }
    else
    {
        #get value of WMI repository corruption status
        [int]$RepositoryCorrupt = Get-CHRegistryValue -RegKey 'HKLM:\SOFTWARE\Microsoft\Wbem\CIMOM' -RegValue 'RepositoryCorruptionReported'

        if($RepositoryCorrupt -eq 0)
        {
            Write-CHLog -Function 'Test-CHWMIHealth' -Message ('Result of WMI repository check is {0}' -f $RepositoryCorrupt)
            Try
            {
                #attempt to read a core class from root\cimv2 namespace
                $null = Get-WmiObject -Class win32_operatingsystem -ErrorAction Stop

                if($script:ClientSettings.WMIWriteRepository -eq $true)
                {
                    #basic test of WMI deems initial success
                    if($RepositoryCorrupt -eq 0 -and (Test-CHWriteWMI -Namespace 'root\cimv2'))
                    {
                                                
                        #If SCCM client is installed, verify WMI core namespace health
                        if($script:SCCMInstalled -eq $true)
                        {
                            #continue testing by attempting write to all CCM namespaces
                            [array]$CCMNamespaces = Get-WmiObject -Namespace root\ccm -Class __namespace -Recurse
                            [bool]$Status = $True
                            ForEach($CCMNamespace in $CCMNamespaces)
                            {
                                if(!(Test-CHWriteWMI -Namespace ('{0}\{1}' -f $CCMNamespace.__NAMESPACE, $CCMNamespace.Name)))
                                {
                                    $Status = $False
                                }
                            }
                            if(!($Status))
                            {
                                Write-CHLog -Function 'Test-CHWMIHealth' -Message 'Unable to write to one or more namespaces in the SCCM namespace root\ccm' 
                            }
                            return $Status
                        }
                        else { return $true }
                    }
                    else
                    {
                        Write-CHLog -Function 'Test-CHWMIHealth' -Message 'Failed to write to default WMI namespace or WMI is corrupt; rebuild of WMI is suggested'
                        return $False
                    }
                }
            }
            Catch
            {
                Write-CHLog -Function 'Test-CHWMIHealth' -Message 'Failed to get basic WMI information'
                return $False
            }
        }
        else
        {
            Write-CHLog -Function 'Test-CHWMIHealth' -Message 'ERROR: WMI is corrupt; rebuild of WMI is suggested'
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
    Get-CHServiceStatus -ServiceName BITS -StartType DelayedAuto -Status Running

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
        [Parameter(Mandatory=$True)][string]$ServiceName,
        [Parameter(Mandatory=$True)][ValidateSet('Automatic','Manual','Disabled','DelayedAuto','NotDisabled')][string]$StartType,
        [Parameter(Mandatory=$True)][ValidateSet('Running','Stopped','NotMonitored')][string]$Status 
    )

    #Convert friendly parameter to numeric values
    Switch ($StartType)
    {
        'DelayedAuto'  {[int]$ExpectedStart = 2}
        'Automatic' {[int]$ExpectedStart = 2}
        'Manual'    {[int]$ExpectedStart = 3}
        'Disabled'  {[int]$ExpectedStart = 4}
        'NotDisabled'  {[int]$ExpectedStart = 0}
    }

    #Bind to the Service object using PoSH Get-Service
    $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    
    #Check to make sure there is a service that was found.
    if($Service)
    {
        
        #Validate that the Automatic Services are configured correctly
        if($ExpectedStart -eq 2)
        {
            #Get the Delayed AutoStart value from the Registry as this is the only way to tell the difference between Automatic and DelayedAuto
            [int]$DelayedAutoStart = Get-CHRegistryValue -RegKey ('HKLM:\SYSTEM\CurrentControlSet\services\{0}' -f $ServiceName) -RegValue 'DelayedAutostart'

            #Validate Automatic is not set for DelyedAutoStart
            if($StartType -eq 'Automatic' -and $DelayedAutoStart -eq 1)
            {
                Write-CHLog -Function 'Get-CHServiceStatus' -Message ('WARNING - {0} service is set to Delayed AutoStart and not expected.' -f $ServiceName)
                Return $False
            }
            
            #Validate Delayed Autostart is set correctly
            if($StartType -eq 'DelayedAuto' -and $DelayedAutoStart -ne 1)
            {
                Write-CHLog -Function 'Get-CHServiceStatus' -Message ('WARNING - {0} is expecting Delayed Autostart, however is not configured correctly.' -f $ServiceName)
                Return $False
            }
        }

        #Get Start Type because the Get-Service does not show this and using WMI could be an issue on some machines.
        # 2=Automatic, 3=Manual, 4=Disabled
        [int]$CurrentStart = Get-CHRegistryValue -RegKey ('HKLM:\SYSTEM\CurrentControlSet\services\{0}' -f $ServiceName) -RegValue 'Start'
        
        #Check StartType and Status match what is expected
        if(($ExpectedStart -eq $CurrentStart -and $Status -eq $Service.Status) -or ($ExpectedStart -eq $CurrentStart -and $Status -eq 'NotMonitored') -or ($CurrentStart -ne 4 -and $ExpectedStart -eq 0))
        {
            Write-CHLog -Function 'Get-CHServiceStatus' -Message ('{0} is configured correctly.' -f $ServiceName)
            Return $True
        }
        else
        {
            Write-CHLog -Function 'Get-CHServiceStatus' -Message ('WARNING - {0} Service not configured correctly' -f $ServiceName)
            Write-CHLog -Function 'Get-CHServiceStatus' -Message ('WARNING - {0} is expected to be set to {1} and currently {2}.' -f $ServiceName, $StartType, $Status)

            #Output some helpful information if the current start type does not match the expected start type
            Switch ($CurrentStart)
            {
                2 {Write-CHLog -Function 'Get-CHServiceStatus' -Message ('WARNING - {0} is set to Automatic and status is currently {1}' -f $ServiceName, $($Service.Status))}
                3 {Write-CHLog -Function 'Get-CHServiceStatus' -Message ('WARNING - {0} is set to Manual and status is currently {1}' -f $ServiceName, $($Service.Status))}
                4 {Write-CHLog -Function 'Get-CHServiceStatus' -Message ('WARNING - {0} is set to Disabled and status is currently {1}' -f $ServiceName, $($Service.Status))}
            }

            Return $False
        }
    }
    else
    {
         Write-CHLog -Function 'Get-CHServiceStatus' -Message ('ERROR - {0} service does not exist as an installed service on this computer.' -f $ServiceName)
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
    Set-CHServiceStatus -ServiceName BITS -StartType Manual -Status Running

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

    PARAM
    (
        [Parameter(Mandatory=$True)][string]$ServiceName,
        [Parameter(Mandatory=$True)][ValidateSet('Automatic','Manual','Disabled','DelayedAuto')][String]$StartType,
        [Parameter(Mandatory=$True)][ValidateSet('Running','Stopped')][string]$Status 
    )

    #Clear any errors
    $Error.Clear()
    
    #Convert friendly parameter to values for the SC command
    Switch ($StartType)
    {
        'DelayedAuto'  {[string]$StartTypeSC = 'delayed-auto'}
        'Automatic' {[string]$StartTypeSC = 'auto'}
        'Manual'    {[string]$StartTypeSC = 'demand'}
        'Disabled'  {[string]$StartTypeSC = 'disabled'}
    }

    #Configure the Windows Service Start type and Status   
     Try
     {
        Write-CHLog -Function 'Set-CHServiceStatus' -Message ('Attempting to set {0} to {1} and {2}' -f $ServiceName, $StartType, $Status)

        #Run SC command because start-service does not support Auto delayed
        [int]$ExitCode = (Start-Process -FilePath "$env:windir\system32\sc.exe" -ArgumentList ('config {0} start= {1}' -f $ServiceName, $StartTypeSC) -WindowStyle Hidden -PassThru -Wait).ExitCode

        If($ExitCode -eq 0)
        {
            #Start or Stop Service based on request
            If($Status -eq 'Running') {Start-Service -Name $ServiceName -ErrorAction Stop }
            If($Status -eq 'Stopped') {Stop-Service -Name $ServiceName -ErrorAction Stop }

            #Check the Service Status
            $ServiceStatus = Get-CHServiceStatus -ServiceName $ServiceName -StartType $StartType -Status $Status

            If($ServiceStatus)
            {
                Write-CHLog -Function 'Set-CHServiceStatus' -Message ('{0} successfully set to {1} and {2}.' -f $ServiceName, $StartType, $Status)

                Return $True
            }
            Else
            {
                Write-CHLog -Function 'Set-CHServiceStatus' -Message ('ERROR - {0} Service was not configured correctly.' -f $ServiceName)
                Return $False
            }
        }
        Else
        {
            Write-CHLog -Function 'Set-CHServiceStatus' -Message ('ERROR - Could not set {0} to a starttype of {1}.  Exit Code ({2})' -f $ServiceName, $StartType, $ExitCode)
            Return $False
        }
     }
     Catch
     {
        #Get first line of error only
        [string]$ErrorMsg = ($Error[0].toString()).Split('.')[0]

        #Catch any error and write tolog
        Write-CHLog -Function 'Set-CHServiceStatus' -Message ('ERROR - {0} Service not configured correctly.  {1}' -f $ServiceName, $ErrorMsg)

        Return $False
     }
   
}

Function Invoke-CHWMIRebuild ()
{
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
    
    if($script:Debug){ Write-CHLog -Function 'Invoke-CHWMIRebuild' -Message 'Information: Starting the process of rebuilding WMI' }

    [string]$WbemPath = "$($env:WINDIR)\system32\wbem"
    [string]$Repository = ('{0}\Repository' -f $WbemPath)

    if($script:Debug){ Write-CHLog -Function 'Invoke-CHWMIRebuild' -Message 'Information: Stop SMS Agent Host if it exists' }
    Try
    {
        $null = Get-Service -Name CcmExec -ErrorAction Stop | Stop-Service -ErrorAction Stop
        if($script:Debug){ Write-CHLog -Function 'Invoke-CHWMIRebuild' -Message 'Information: Stop SMS Agent Host service was successful' }
    }
    Catch
    {
        Write-CHLog -Function 'Invoke-CHWMIRebuild' -Message 'Warning: Stop SMS Agent Host service was not successful'
    }

    #stop CCMSETUP process and delete service if it exists
    if($script:Debug){ Write-CHLog -Function 'Invoke-CHWMIRebuild' -Message 'Information: Stop CCMSETUP Service and delete if it exists' }

    if((Get-Service -Name ccmsetup -ErrorAction SilentlyContinue) -ne $null)
    {
        $null = Get-Process -Name ccmsetup -ErrorAction SilentlyContinue | Stop-Process -ErrorAction SilentlyContinue -Force
                
        #delete the ccmsetup service
        [object]$Status = Start-Process -FilePath "$env:windir\system32\sc.exe" -ArgumentList 'delete ccmsetup' -WindowStyle Hidden -PassThru -Wait
        if($Status.ExitCode -eq 0)
        {
            if($script:Debug){ Write-CHLog -Function 'Invoke-CHWMIRebuild' -Message 'Information: CCMSETUP service was deleted' }
        }
        else
        {
            Write-CHLog -Function 'Invoke-CHWMIRebuild' -Message 'Warning: CCMSETUP service was not deleted; continuing to repair WMI'
        }

        #cleaning up variable
        Remove-Variable -Name 'Status'
    }

    #uninstall SCCM client if the service exists
    if(Get-Service -Name ccmexec -ErrorAction SilentlyContinue){ Invoke-CHClientAction -Action Uninstall }

    #reset security on the WMI, Windows Update, and BITSF services
    [array]$Services = @('winmgmt','wuauserv','bits')
                
    foreach($Service in $Services)
    {
        Write-CHLog -Function 'Invoke-CHWMIRebuild' -Message ('Information: The current security descriptor for the {0} Service is {1}' -f $Service, (& "$env:windir\system32\sc.exe" sdshow $Service))
        Write-CHLog -Function 'Invoke-CHWMIRebuild' -Message ('Information: Setting default security descriptor on {0} to D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)' -f $Service)
        [object]$Status = Start-Process -FilePath "$env:windir\system32\sc.exe" -ArgumentList ('sdset {0} D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)' -f $Service) -WindowStyle Hidden -PassThru -Wait
        Write-CHLog -Function 'Invoke-CHWMIRebuild' -Message ('Information: The exit code to set the security descriptor is {0}' -f $($Status.ExitCode))
    }

    #cleaning up variable
    Remove-Variable -Name 'Status'

    #Re-enabling DCOM
    if(Set-CHRegistryValue -RegKey 'HKLM:\SOFTWARE\Microsoft\OLE' -RegValue 'EnableDCOM' -Data 'Y' -DataType 'string')
    {
        if($script:Debug){ Write-CHLog -Function 'Invoke-CHWMIRebuild' -Message 'Information: Successfully enabled DCOM' }
    }
    else { Write-CHLog -Function 'Invoke-CHWMIRebuild' -Message 'Warning: DCOM not enabled successfully' }

    #Resetting DCOM Permissions
    Write-CHLog -Function 'Invoke-CHWMIRebuild' -Message 'Information: Resetting DCOM Permissions'
                
    [array]$RegEntries = @('DefaultLaunchPermission','MachineAccessRestriction','MachineLaunchRestriction')
    foreach($RegEntry in $RegEntries){
        [object]$Status = Start-Process -FilePath "$env:windir\system32\reg.exe" -ArgumentList ('delete HKLM\software\microsoft\ole /v {0} /f' -f $RegEntry) -WindowStyle Hidden -PassThru -Wait
        Write-CHLog -Function 'Invoke-CHWMIRebuild' -Message ('Information: The exit code to delete {0} from HKLM:\software\microsoft\ole is {1}' -f $RegEntry, $($Status.ExitCode))
    }

    #Rebuild WMI using WINMGMT utility (supported in each OS with version 6 or higher)
    if($script:Debug){ Write-CHLog -Function 'Invoke-CHWMIRebuild' -Message 'Refreshing WMI ADAP' }
    [object]$Status = Start-Process -FilePath ('{0}\wmiadap.exe' -f $WbemPath) -ArgumentList '/f' -WindowStyle Hidden -PassThru -Wait
    Write-CHLog -Function 'Invoke-CHWMIRebuild' -Message ('Information: The exit code to Refresh WMI ADAP is {0}' -f $($Status.ExitCode))

    if($script:Debug){ Write-CHLog -Function 'Invoke-CHWMIRebuild' -Message 'Registering WMI' }
    [object]$Status = Start-Process -FilePath "$env:windir\system32\regsvr32.exe" -ArgumentList '/s wmisvc.dll' -WindowStyle Hidden -PassThru -Wait
    Write-CHLog -Function 'Invoke-CHWMIRebuild' -Message ('Information: The exit code to Register WMI is {0}' -f $($Status.ExitCode))

    if($script:Debug){ Write-CHLog -Function 'Invoke-CHWMIRebuild' -Message 'Resyncing Performance Counters' }
    [object]$Status = Start-Process -FilePath ('{0}\winmgmt.exe' -f $WbemPath) -ArgumentList '/resyncperf' -WindowStyle Hidden -PassThru -Wait
    Write-CHLog -Function 'Invoke-CHWMIRebuild' -Message ('Information: The exit code to Resync Performance Counters is {0}' -f $($Status.ExitCode))

    if($script:Debug){ Write-CHLog -Function 'Invoke-CHWMIRebuild' -Message 'Attempting salvage of WMI repository using winmgmt /salvagerepository' }
    [object]$Status = Start-Process -FilePath ('{0}\winmgmt.exe' -f $WbemPath) -ArgumentList '/salvagerepository' -WindowStyle Hidden -PassThru -Wait
    Write-CHLog -Function 'Invoke-CHWMIRebuild' -Message ('Information: The exit code to Salvage the WMI Repository is {0}' -f $($Status.ExitCode))

    #unregistering atl.dll
    [object]$Status = Start-Process -FilePath "$env:windir\system32\regsvr32.exe" -ArgumentList "/u $env:windir\system32\atl.dll /s" -WindowStyle Hidden -PassThru -Wait
    Write-CHLog -Function 'Invoke-CHWMIRebuild' -Message ('Information: The exit code to Unregister ATL.DLL is {0}' -f $($Status.ExitCode))

    #registering required DLLs
    [array]$DLLs = @('scecli.dll','userenv.dll','atl.dll')
                
    foreach($Dll in $DLLs)
    {
        [object]$Status = Start-Process -FilePath "$env:windir\system32\regsvr32.exe" -ArgumentList ('/s {0}\system32\{1}' -f $env:windir, $Dll) -WindowStyle Hidden -PassThru -Wait
        Write-CHLog -Function 'Invoke-CHWMIRebuild' -Message ('Information: The exit code to Register {0} is {1}' -f $DLL, $($Status.ExitCode))
    }

    #Register WMI Provider
    [object]$Status = Start-Process -FilePath ('{0}\wmiprvse.exe' -f $WbemPath) -ArgumentList '/regserver' -WindowStyle Hidden -PassThru -Wait
    Write-CHLog -Function 'Invoke-CHWMIRebuild' -Message ('Information: The exit code to Register WMI Provider is {0}' -f $($Status.ExitCode))
    
    #Restart WMI Service
    Try
    {
        Write-CHLog -Function 'Invoke-CHWMIRebuild' -Message 'Restarting the WMI Service'
        
        [string]$SvcName = 'winmgmt'
        
        # Get dependent services
        [array]$DepSvcs = Get-Service -name $SvcName -dependentservices | Where-Object {$_.Status -eq 'Running'} | Select-Object -ExpandProperty Name
 
        # Check to see if dependent services are started
        if ($DepSvcs -ne $null) 
        {
	        # Stop dependencies
	        foreach ($DepSvc in $DepSvcs)
	        {
                Write-CHLog -Function 'Invoke-CHWMIRebuild' -Message ('Stopping {0} as it is a dependent of the WMI Service' -f $($DepSvc.Name))
		        $null = Stop-Service -InputObject $DepSvc.Name -ErrorAction Stop
		        do
		        {
			        [object]$Service = Get-Service -name $DepSvc.Name | Select-Object -ExpandProperty Status
			        Start-Sleep -seconds 1
		        }
		        until ($Service.Status -eq 'Stopped')
	        }
        }
 
        # Restart service
        $null = Restart-Service -InputObject $SvcName -Force -ErrorAction Stop
        do
        {
	        $Service = Get-Service -name $SvcName | Select-Object -ExpandProperty Status
	        Start-Sleep -seconds 1
        }
        until ($Service.Status -eq 'Running')
                
        # We check for Auto start flag on dependent services and start them even if they were stopped before
        foreach ($DepSvc in $DepSvcs)
        {
	        $StartMode = Get-WmiObject -Class win32_service -Filter ("NAME = '{0}'" -f $($DepSvc.Name)) | Select-Object -ExpandProperty StartMode
	        if ($StartMode.StartMode -eq 'Auto') 
            {
		        
                Write-CHLog -Function 'Invoke-CHWMIRebuild' -Message ('Starting {0} after restarting WMI Service' -f $($DepSvc.Name))
                $null = Start-Service -InputObject $DepSvc.Name -ErrorAction Stop
		        do
		        {
			        $Service = Get-Service -name $DepSvc.Name | Select-Object -ExpandProperty Status
			        Start-Sleep -seconds 1
		        }
		        until ($Service.Status -eq 'Running')
	        }
        }
    }
    Catch
    {
        Write-CHLog -Function 'Invoke-CHWMIRebuild' -Message 'ERROR - Restart of WMI service failed'
    }

    Write-CHLog -Function 'Invoke-CHWMIRebuild' -Message 'ACTION: Rebuild of WMI completed; please reboot system'

    #Run GPUpdate if on Domain
    if((Get-CHRegistryValue -RegKey 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters' -RegValue 'Domain') -ne '')
    {
        $null = & "$env:windir\system32\gpupdate.exe"
    }
    
    Write-CHLog -Function 'Invoke-CHWMIRebuild' -Message 'Testing WMI Health post repair'

    if(Test-CHWMIHealth -eq $False)
    {
        Write-CHLog -Function 'Invoke-CHWMIRebuild' -Message 'ERROR - WMI Verification failed; reseting the repository with winmgmt /resetrepository'

        [object]$Status = Start-Process -FilePath ('{0}\winmgmt.exe' -f $WbemPath) -ArgumentList '/resetrepository' -WindowStyle Hidden -PassThru -Wait
        Write-CHLog -Function 'Invoke-CHWMIRebuild' -Message ('Information: The exit code to Reset the WMI Repository is {0}' -f $($Status.ExitCode))

        if($Status.ExitCode -eq 0)
        {
            Write-CHLog -Function 'Invoke-CHWMIRebuild' -Message 'WMI reset successfully; verifying repository again'

            if(Test-CHWMIHealth -eq $false)
            {
                Write-CHLog -Function 'Invoke-CHWMIRebuild' -Message 'ERROR - WMI Verification failed after reseting the repository with winmgmt /resetrepository'
                [bool]$WMIHealth = $false
            }
            else
            {
                [bool]$WMIHealth = $true
            }
        }
    }
    else { [bool]$WMIHealth = $true }

    #increment WMI rebuild count by 1 and write back to registry; it is important to track this number no matter success or failure of the rebuild
    [int]$WMIRebuildCount = 1 + (Get-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_WMIRebuildAttempts')
    Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_WMIRebuildAttempts' -Data $WMIRebuildCount -DataType 'string'

    Write-CHLog -Function 'Invoke-CHWMIRebuild' -Message ('Information: WMI has been rebuilt {0} times by the PFE Remediation for Configuration Manager script' -f $WMIRebuildCount)

    if($WMIHealth)
    {
        Write-CHLog -Function 'Invoke-CHWMIRebuild' -Message 'Information: WMI Verification successful after reseting the repository with winmgmt /resetrepository'

        if($script:Debug){ Write-CHLog -Function 'Invoke-CHWMIRebuild' -Message 'Information: Detecting Microsoft Policy Platform installation; if installed will attempt to compile MOF/MFL files' }
        if($script:Debug){ Write-CHLog -Function 'Invoke-CHWMIRebuild' -Message 'Information: This is done to prevent ccmsetup from erroring when trying to compile DiscoveryStatus.mof and there are issues with the root\Microsoft\PolicyPlatform namespace' }

        if(Test-Path -Path "$env:ProgramFiles\Microsoft Policy Platform" -ErrorAction SilentlyContinue){
            [array]$MPPFiles = Get-ChildItem -Path "$env:ProgramFiles\Microsoft Policy Platform" | Where-Object { ($_.Extension -eq '.mof' -or $_.Extension -eq '.mfl') -and $_.Name -notlike '*uninst*' } | ForEach-Object { $_.fullname }
            foreach($MPPFile in $MPPFiles)
            {
                        
                [object]$Status = Start-Process -FilePath ('{0}\mofcomp.exe' -f $WbemPath) -ArgumentList ('""{0}""' -f $MPPFile) -WindowStyle Hidden -PassThru -Wait
                Write-CHLog -Function 'Invoke-CHWMIRebuild' -Message ('Information: The exit code to MOFCOMP {0} is {1}' -f $MPPfile, $($Status.ExitCode))
            }
        }
        else
        {
            Write-CHLog -Function 'Invoke-CHWMIRebuild' -Message 'Warning: Unable to get Microsoft Policy Platform files'
        }
        return $True
    }
    else { return $false }
}

Function Invoke-CHClientAction ()
{  
    <#
	.SYNOPSIS
	Install, uninstall, or repair the SCCM client

	.DESCRIPTION
	Function to install the most current version of the SCCM client

	.EXAMPLE
	Invoke-CHClientAction -Action Install

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
        [ValidateSet('Install','Uninstall','Repair')][string]$Action
    )

    Write-CHLog -Function 'Invoke-CHClientAction' -Message ('The client action {0} has been initiated' -f $Action)

    If(($script:ClientSettings.WorkstationRemediation -eq $TRUE -and $script:OSType -eq 'workstation') -or ($script:ClientSettings.ServerRemediation -eq $TRUE -and $script:OSType -eq 'server')) 
    {
        
        Write-CHLog -Function 'Invoke-CHClientAction' -Message ('Remediation enabled; beginning ConfigMgr client {0}' -f $Action)

        #Get current Date and Time
        Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastAction' -Data ('Client {0}' -f $Action) -DataType string
        Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastDate' -Data (Get-Date -format yyyy-MM-dd) -DataType string
        Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastTime' -Data (Get-Date -format HH:mm:ss) -DataType string

        $ClientInstallCount = Get-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_ClientInstallCount' -ErrorAction SilentlyContinue 
        
        if ($ClientInstallCount)
        {
            Write-CHLog -Function 'Invoke-CHClientAction' -Message ('The client has been installed {0} number of times.' -f $ClientInstallCount)
        }
        else
        {
            Write-CHLog -Function 'Invoke-CHClientAction' -Message 'The PFE_ClientInstallCount property does not exist. Creating PFE_ClientInstallCount property and setting value to 0'
            try
            {
                Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_ClientInstallCount' -Data 0
                $ClientInstallCount = Get-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_ClientInstallCount'
                Write-CHLog -Function 'Invoke-CHClientAction' -Message 'Created PFE_ClientInstallCount'

            }
            catch
            {
                Write-CHLog -Function 'Invoke-CHClientAction' -Message 'ERROR: Failed to create PFE_ClientInstallCount property.'
            }
        }

        
        Stop-Service -Name 'CCMSetup' -Force -ErrorAction SilentlyContinue
        Stop-Process -Name 'CCMSetup' -Force -ErrorAction SilentlyContinue
        Stop-Process -Name 'CCMRestart' -Force -ErrorAction SilentlyContinue

        if(Test-Path -Path "$env:windir\ccmsetup\ccmsetup.exe")
        {
            [string]$ClientActionCommand = "$env:windir\ccmsetup\ccmsetup.exe"
        }
        else
        { 
            If(Test-Path -Path ('\\{0}\PFEClient$\ccmsetup.exe' -f $($script:ClientSettings.PrimarySiteServer)))
            {
                [string]$ClientActionCommand = ('\\{0}\PFEClient$\ccmsetup.exe' -f $($script:ClientSettings.PrimarySiteServer)) 
            }
            else
            {
                Write-CHLog -Function 'Invoke-CHClientAction' -Message ('ERROR: no CCMSetup.exe found at {0}\PFEClient$' -f $($script:ClientSettings.PrimarySiteServer))
                Write-CHEventLog -Function 'Invoke-CHClientAction' -Message ('Error - no CCMSetup.exe found at {0}\PFEClient$' -f $($script:ClientSettings.PrimarySiteServer)) -IDType Error -Enabled $script:ClientSettings.EventLog
                
                return $false
            }
        }

        #Convert friendly parameter to values for the SC command
        Switch ($Action)
        {
            'Install'   {[string]$ClientActionArgs = ('{0} SMSSITECODE={1} {2}' -f $($script:ClientSettings.ExtraEXECommands), $($script:SiteCode), $($script:ClientSettings.ExtraMSICommands))}
            'Uninstall' {[string]$ClientActionArgs = '/Uninstall'}
            'Repair'    {[string]$ClientActionArgs = ('{0} SMSSITECODE={1} RESETKEYINFORMATION=TRUE REMEDIATE=TRUE {2}' -f $($script:ClientSettings.extraEXECommands), $($script:SiteCode), $($script:ClientSettings.extraMSICommands))}
        }

        Write-CHLog -Function 'Invoke-CHClientAction' -Message ('Starting Client {0} with command line {1} {2}' -f $Action, $ClientActionCommand, $ClientActionArgs)
        
        [int]$ClientActionExitCode = (Start-Process -FilePath $ClientActionCommand -ArgumentList $ClientActionArgs -Wait -NoNewWindow -PassThru ).ExitCode

        if($Action -ne 'Uninstall')
        {
            if(($ClientActionExitCode -eq 0) -and ($ClientActionArgs.ToLower() -contains '/noservice'))
            {
                #Client install complete
                Write-CHLog -Function 'Invoke-CHClientAction' -Message ('{0} of ConfigMgr Client complete' -f $Action)
                # Increment Client Count 
                [int]$NewClientInstallCount = 1 + (Get-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_ClientInstallCount')
                Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_ClientInstallCount' -Data $NewClientInstallCount
                
                return $true
            }
            elseif(($ClientActionExitCode -eq 0) -and ($ClientActionArgs.ToLower() -notcontains '/noservice'))
            {
                #client installing
                Write-CHLog -Function 'Invoke-CHClientAction' -Message ('{0} of ConfigMgr Client has begun' -f $Action)
                Start-Sleep -Seconds 30
                [string]$ProcessID = Get-Process -name 'ccmsetup' -ErrorAction SilentlyContinue | ForEach-Object {$_.Id}
                if($ProcessID.Trim() -eq '')
                {
                    Write-CHLog -Function 'Invoke-CHClientAction' -Message 'No Process ID found for CCMSETUP'
                    Write-CHLog -Function 'Invoke-CHClientAction' -Message 'ERROR - CCMSETUP not launched successfully, validate command line is correct'
                    return $false
                }
                else
                {
                    Write-CHLog -Function 'Invoke-CHClientAction' -Message ('Monitoring Process ID {0} for CCMSETUP to complete' -f $ProcessID)
                    Write-CHLog -Function 'Invoke-CHClientAction' -Message ('ConfigMgr client {0} is running' -f $Action)
                    Wait-Process -Id $ProcessID
                    Write-CHLog -Function 'Invoke-CHClientAction' -Message ('ConfigMgr client {0} complete' -f $Action)

                    #Service Startup Checks
                    try
                    {
                        $null = Get-Process -name 'ccmexec' -ErrorAction Stop
                        $null = Get-Service -name 'ccmexec' -ErrorAction Stop

                        # Increment Client Count 
                        [int]$NewClientInstallCount = 1 + (Get-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_ClientInstallCount')
                        Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_ClientInstallCount' -Data $NewClientInstallCount

                        return $true
                    }
                    catch
                    {
                        Write-CHLog -Function 'Invoke-CHClientAction' -Message ('ERROR - Service check after client {0} failed' -f $Action)
                        return $false
                    }
                    #Detect Application that needs to install
                }
            }
            else
            {
                #client install failed
                Write-CHLog -Function 'Invoke-CHClientAction' -Message ('ERROR - {0} of ConfigMgr Client has failed' -f $Action)
                return $false
            }
        }
        else
        {
            if($ClientActionExitCode -eq 0) 
            {
                Write-CHLog -Function 'Invoke-CHClientAction' -Message 'System Center ConfigMgr Client successfully uninstalled'
                $script:SCCMInstalled = $false
                #If Policy Platform is installed, Remove it
                Try
                {
                    [string]$FilePath = Get-ChildItem -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall | where-object { $_.GetValue('DisplayName') -eq 'Microsoft Policy Provider' } | ForEach-Object { $_.GetValue('UninstallString') }
                    [string]$ProcessName = $FilePath.Substring(0,$FilePath.IndexOf(' '))
                    [string]$ArgList = $FilePath.Substring($FilePath.IndexOf('/'),$FilePath.Length-$FilePath.IndexOf('/'))
                    [int]$PolProvUninstall = (Start-Process -FilePath $ProcessName -ArgumentList $ArgList -Wait -NoNewWindow -PassThru ).ExitCode
                    If($PolProvUninstall -eq 0) 
                    {
                        Write-CHLog -Function 'Invoke-CHClientAction' -Message 'Microsoft Policy Platform successfully uninstalled'
                    }
                    Else 
                    {
                        Write-CHLog -Function 'Invoke-CHClientAction' -Message ('ERROR - Microsoft Policy Platform failed to uninstall with exit code {0}' -f $PolProvUninstall)
                    }
                }
                Catch 
                {
                    Write-CHLog -Function 'Invoke-CHClientAction' -Message 'ERROR - Could not bind to registry to do uninstall of Microsoft Policy Platform.  Either cannot access registry, or the MPP is not installed'
                }
            }
            Else 
            {
                Write-CHLog -Function 'Invoke-CHClientAction' -Message 'ERROR - Failed to uninstall System Center ConfigMgr Client'
            }
        }
    }
    else 
    {
        Write-CHLog -Function 'Invoke-CHClientAction' -Message ('WARNING - Remediation has been disabled for this hardware type. Will not {0} client' -f $Action)
        return $false
    }

    #Update Registry with current status and date\time
    Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastAction' -Data ('Client {0}' -f $Action) -DataType string
    Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastDate' -Data (Get-Date -format yyyy-MM-dd) -DataType string
    Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastTime' -Data (Get-Date -format HH:mm:ss) -DataType string
}

Function Test-CHStaleLog()
{
<#
    .SYNOPSIS
    Checks to see whether the specified log file has shown activity within the provided timeframe.
    
    .DESCRIPTION
    This function will check to see if a log file has been written to in a certain amount of time.  If it has not,
    a repair will be run on the client.  If the log file does not exist, a repair will be run on the client if there
    has not been activity in the ccmsetup log within the last 24 hours.

    Return value will be boolean based and a TRUE should flag a CCMRepair.
    
    .EXAMPLE
    Test-CHStaleLog -LogFileName ccmexec -DaysStale 2

    .PARAMETER strLogFileName
    File name of the log that would would like to test for inactivity.  Name should NOT include the '.log' at the end.

    .PARAMETER intDaysStale
    Number of days of inactivity that you would consider the specified log stale.

    
    .DEPENDENT FUNCTIONS
    Write-CHLog
    Set-CHRegistryValue
    Get-CHRegistryValue

    #>

    PARAM
    (
         [Parameter(Mandatory=$True,
        ValueFromPipelineByPropertyName=$True)]
        [string]$LogFileName,

        [Parameter(Mandatory=$True,
        ValueFromPipelineByPropertyName=$True)]
        [int]$DaysStale

    )
    
    Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastAction' -Data 'Stale Logs' -DataType string
    Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastDate' -Data (Get-Date -format yyyy-MM-dd) -DataType string
    Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastTime' -Data (Get-Date -format HH:mm:ss) -DataType string

    #get log file location from registry
    [string]$CMInstallKey = 'HKLM:\SOFTWARE\Microsoft\CCM\Logging\@Global'
    [string]$CMClientInstallLog = "$env:windir\ccmsetup\Logs\ccmsetup.log"
    
    if(Test-Path -Path $CMInstallKey)
    {
        [string]$CMInstallLocation = Get-CHRegistryValue -RegKey $CMInstallKey -RegValue 'LogDirectory'

        [string]$Log = ('{0}\{1}.log' -f $CMInstallLocation, $LogFileName)
        Write-CHLog -Function 'Test-CHStaleLog' -Message ('Check {0} for activity' -f $Log)

        if(Test-Path -Path $Log) 
        {
            [datetime]$dtmLogDate = (Get-Item -Path $Log).LastWriteTime
            [int]$DaysDiff = (New-TimeSpan -Start $dtmLogDate -End (Get-Date -format yyyy-MM-dd)).Days
            if($DaysDiff -gt $DaysStale) 
            {
                #Unhealthy
                Write-CHLog -Function 'Test-CHStaleLog' -Message ('{0}.log is not active' -f $LogFileName)
                Write-CHLog -Function 'Test-CHStaleLog' -Message ('{0}.log last date modified is {1}' -f $LogFileName, $LogDate)
                Write-CHLog -Function 'Test-CHStaleLog' -Message "Current Date and Time is $(get-date)"
                return $true
            }
            else
            {
                #Healthy
                Write-CHLog -Function 'Test-CHStaleLog' -Message ('{0}.log is active' -f $LogFileName)
                return $false
            }
        }
        else
        {
            #Log File Missing
            Write-CHLog -Function 'Test-CHStaleLog' -Message ('{0}.log is missing; checking for recent ccmsetup activity' -f $LogFileName)
            if(Test-Path -Path $CMClientInstallLog) 
            {
                [datetime]$dtmCMClientInstallLogDate = (Get-Item -Path $CMClientInstallLog).LastWriteTime
                [int]$ClientInstallHours = (New-TimeSpan -Start (Get-Date -format yyyy-MM-dd) -End $dtmCMClientInstallLogDate).TotalHours
                if($ClientInstallHours -lt 24) 
                {
                    #Log has been written to recently / client has been installed recently
                    Write-CHLog -Function 'Test-CHStaleLog' -Message 'CCMSetup activity detected within last 24 hours, will not attempt to repair'
                    return $false
                }
                else
                {
                    #Log has not been written to recently / client has not been installed or repaired recently
                    Write-CHLog -Function 'Test-CHStaleLog' -Message 'CCMSetup activity not detected within last 24 hours, will attempt to repair'
                    return $true
                }
            }
            else
            {
                #Client Never Installed
                Write-CHLog -Function 'Test-CHStaleLog' -Message ('CCMSetup.log not found in {0}, will attempt to install client' -f $CMClientInstallLog)
                return $true
            }
        }
    }
    else
    {
        Write-CHLog -Function 'Test-CHStaleLog' -Message 'Error - No log file directory found'
        return $true
    }
}

 Function Get-CHini()
{
    <#
    .SYNOPSIS
    Reads an ini file and returns back the value of the provided key
    .DESCRIPTION
    Parses through a provided ini file and finds the value of a key under a particular section of the file
    .EXAMPLE
    Get-CHINI -parameter "value"
    .EXAMPLE
    Get-CHINI -File "c:\Windows\smscfg.ini" -Section "Configuration - Client Properties" -Key "SID"
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
        [string]$File,

        [Parameter(Mandatory=$True,
        ValueFromPipelineByPropertyName=$True)]
        [string]$Section,
        
        [Parameter(Mandatory=$True,
        ValueFromPipelineByPropertyName=$True)]
        [string]$Key

    )
 
    <#Test settings to run without function call
	$File = "c:\Windows\smscfg.ini"
    $Section = "Configuration - Client Properties"
    $Key = "SID"
	#>
        
    If(Test-Path -Path $File) 
    {
        Write-CHLog -Function 'Get-CHINI' -Message ('{0} exists' -f $File)
        Write-CHLog -Function 'Get-CHINI' -Message ('Searching for {0} in [{1}] section' -f $Key, $Section)
        [object]$INI = New-Object -TypeName psobject
               
        switch -regex -file $File 
        {
            '^\[(.+)\]' 
            { 
                #Section
                $INISection = $matches[1]
            }
            '(.+?)\s*=(.*)' 
            {
                #Key
                $name,$value = $matches[1..2]
                $INI | Add-Member -MemberType NoteProperty -Name ('{0}.{1}' -f $INISection, $name) -Value $value
            }
        }
    
        #$Value = $INI[$Section][$Key]
        $Value = $INI.(('{0}.{1}' -f $Section, $key))
        If($Value -eq $NULL) 
        {
            Write-CHLog -Function 'Get-CHINI' -Message ('{0} value is blank' -f $Key)
        }
        Else 
        {
            Write-CHLog -Function 'Get-CHINI' -Message ('{0} value found' -f $Key)
            Write-CHLog -Function 'Get-CHINI' -Message ('{0} = {1}' -f $Key, $Value)
            return $Value
        }
    }

    Else 
    {
        Write-CHLog -Function 'Get-CHINI' -Message ('{0} does not exist' -f $File)
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
    
    Try
    {
        #Create an arry of all the Application CI Assignments from the local Policy
        [array]$AppDeployments = $null
        [array]$AppDeployments = Get-WmiObject -Namespace root\CCM\Policy\Machine\ActualConfig -Query 'Select * from CCM_ApplicationCIAssignment' -ErrorAction SilentlyContinue

        if($AppDeployments)
        {
            #Create an array of all the Application Policy stored in the ClientSDK 
            [array]$AppPolicy = Get-WmiObject -Namespace root\CCM\ClientSDK -Query 'SELECT * FROM CCM_ApplicationPolicy' -ErrorAction Stop

            #Loop through each AppDeployment Policy to see if it has an entry in the ClientSDK
        
            ForEach ($AppDeployment in $AppDeployments)
            {
                #Pull the Application Unique ID from the machine policy to use for comparison
                [string]$CIXML = $AppDeployment.AssignedCIs[0]
                [int]$ModelStart = $CIXML.indexof('<ModelName>')
                [int]$ModelFinish = $CIXML.indexof('</ModelName>')
                [string]$CIID = $CIXML.Substring($ModelStart + 11, $ModelFinish - ($ModelStart + 11))
        
                #Set to False and wait to be proven wrong
		        [bool]$AppPolicyMatch = $FALSE

                #Loop throgh each Application Policy in ClientSDK looking for a match
                ForEach ($AppPolicy in $AppPolicy)
                {
                    #If there is a match set AppPolicyMatch to true
                    If (($AppPolicy.ID -eq $CIID) -and ($AppPolicy.IsMachineTarget)){$AppPolicyMatch=$TRUE}
                }

                #If we did not find a match, set Function to False and exit as it only takes one to error
                If(!($AppPolicyMatch))
                {
                    Write-CHLog -Function 'Test-CHAppPolicy' -Message 'Application Policy does not match Deployment Policy, possible CI Corruption.'
                    Return $False
                }
            }
        }

        #If we made it through the loop without and error, then all policies exists
        Return $True
    }
    Catch
    {
        #Get first line of error only
        [string]$ErrorMsg = ($Error[0].toString()).Split('.')[0]

        Write-CHLog -Function 'Test-CHAppPolicy' -Message ('ERROR - Check Application policy failed with error ({0})' -f $ErrorMsg)
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
    [string]$CCMInstallDir = Get-CHRegistryValue -RegKey 'HKLM:\SOFTWARE\Microsoft\SMS\Client\Configuration\Client Properties' -RegValue 'Local SMS Path'
    
    If(($CCMInstallDir) -and ($CCMInstallDir -ne 'Error'))
    {
        #Set Variable for the Application Intent Evaluation log file
        [string]$LogFile = $CCMInstallDir + 'Logs\AppIntentEval.log'

        #Validate Log file exists and if not cacle
        If (Test-Path -Path $LogFile)
        {
            #Get the Current Date and Time
            [datetime]$dtmCurrentDate = Get-Date

            #Get the last Modified time for the log file
            [datetime]$dtmModifiedDate = (Get-Item -Path $LogFile).LastWriteTime
        
            Write-CHLog -Function 'Test-CHAppIntentEval' -Message ('Last Modified time for AppIntentEval is {0}.' -f $dtmModifiedDate)
            Write-CHLog -Function 'Test-CHAppIntentEval' -Message ('Current Time is {0}.' -f $dtmCurrentDate)

            #Get the time in minutes since the file was last modified
            [int]$TimeSinceModified = (New-TimeSpan -Start $dtmModifiedDate -End $dtmCurrentDate).TotalMinutes

            Write-CHLog -Function 'Test-CHAppIntentEval' -Message ('Last modified {0} minutes ago.' -f $TimeSinceModified)

            #If the time is less than 5 min exit with True.
            If($TimeSinceModified -le 5){Return $True}

        }
        Else
        {
            #Log files does not exists.  This could be expected for newly installed clients.
            Write-CHLog -Function 'Test-CHAppIntentEval' -Message (' {0} file does not exist.  No further action needed for AppIntentEval.' -f $LogFile)
            Return $True
        }
    }
    Else
    {
        #exit if we cannot get an CCMInstall Directory from Registry
        Write-CHLog -Function 'Test-CHAppIntentEval' -Message 'Warning - Unable to find ConfigMgr Install Directory from Registry.  Exit function.'
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

    Write-CHLog -Function 'Test-CHLantern' -Message 'Checking Application Policy.'

    #Run Function to check Application Policy
    [bool]$AppPolicy = Test-CHAppPolicy

    #testing function by forcing a bad policy check.
    #$AppPolicy = $false

    #Check for Application Policy, if there is no Policy will assume everything is working.
    If (!($AppPolicy))
    {
        Write-CHLog -Function 'Test-CHLantern' -Message 'There was Application Policy conflict found.  Will trigger Application Deployment Evaluation.'

        #Call Application Deployment Evaluation
        $null = ([wmiclass]'root\ccm:SMS_Client').TriggerSchedule('{00000000-0000-0000-0000-000000000121}')

        #Sleep for 2 min to allow for Application Deployment to complete
        Write-CHLog -Function 'Test-CHLantern' -Message 'Waiting for 2 minutes to allow Application Deployment Evaluation to Complete.'
        Start-Sleep -Seconds 120

        #Check if AppIntentEval.log is updated
        #[bool]$AppIntentUpdated = Test-CHAppIntentEval

        If(Test-CHAppIntentEval)
        {
            #All is well, return healthy
            Write-CHLog -Function 'Test-CHLantern' -Message 'Client appears to be healthy.  Exiting Application Policy Check.'
            Return $True
        }
        Else
        {
            #AppIntent Eval does not appear to be heatlhy.  Need to repair the client.
            Write-CHLog -Function 'Test-CHLantern' -Message 'Client does not appear to be healthy.  Requesting a repair of the client.'

            #Repair CCM Client needed and force the ccmstore.sdf to be replaced
            Set-CHRegistryValue -RegKey 'HKLM:\SOFTWARE\Microsoft\CCMSetup' -RegValue 'CcmStore.sdf' -Data 'corrupted' -DataType string

            Return $False
        }
    }
    Else
    {
        #All is well, return healthy
        Write-CHLog -Function 'Test-CHLantern' -Message 'No Application Policy conflict found.  Client appears to be healthy.'
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
        [Parameter(ValueFromPipelineByPropertyName=$True)][string]$ACPArguments,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True)][string]$ACPServiceName
    )

    #Clear any errors
    $Error.Clear()
    
    Write-CHLog -Function 'Invoke-CHACPInstall' -Message 'ACP Client needs to be installed.'
    Write-CHLog -Function 'Invoke-CHACPInstall' -Message ('{0} client will be repaired if remediation is enabled' -f $ACPServiceName)

    #Write PFE Status to Registry
    Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastAction' -Data 'ACP Repair' -DataType string
    Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastDate' -Data (Get-Date -format yyyy-MM-dd) -DataType string
    Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastTime' -Data (Get-Date -format HH:mm:ss) -DataType string


    if(($script:OSType -eq 'workstation' -and $script:ClientSettings.WorkstationRemediation -eq $True) -or ($script:OSType -eq 'server' -and $script:ClientSettings.ServerRemediation -eq $True)){
        Try{
            #Check for commandline parameters
            If($ACPArguments -ne ''){
                 Write-CHLog -Function 'Invoke-CHACPInstall' -Message ('Installing ACP Client using the file {0} and commandline {1}.' -f $ACPSetup, $ACPArguments)
            
                #Run the ACP Install command
                [object]$Process = Start-Process -FilePath ('{0}' -f $ACPSetup) -ArgumentList ('{0}' -f $ACPArguments) -WindowStyle Hidden -PassThru -Wait
                [int]$ExitCode = $Process.ExitCode
            }
            Else{
                 Write-CHLog -Function 'Invoke-CHACPInstall' -Message ('Installing ACP Client using the file {0}.' -f $ACPSetup)
            
                #Run the ACP Install command
                [object]$Process = Start-Process -FilePath ('{0}' -f $ACPSetup) -WindowStyle Hidden -PassThru -Wait
                [int]$ExitCode = $Process.ExitCode
            }

            #Check the status of the install
            If($ExitCode -eq 0){
                Write-CHLog -Function 'Invoke-CHACPInstall' -Message ('Installation of {0} Client has completed, checking service status.' -f $ACPServiceName)

                #Installation is complete, now check to see if the service is started.
                If(Get-CHServiceStatus -ServiceName $ACPServiceName -StartType $script:ClientSettings.ACPServiceStartType -Status Running){
                    Write-CHLog -Function 'Invoke-CHACPInstall' -Message ('Installation of {0} Client has completed successfully.' -f $ACPServiceName)
            
                    #Write PFE Status to Registry
                    Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_ACPStatus' -Data 'Healthy' -DataType string
                    Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastDate' -Data (Get-Date -format yyyy-MM-dd) -DataType string
                    Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastTime' -Data (Get-Date -format HH:mm:ss) -DataType string

                    Return $True
                }
                Else{
                    If(Set-CHServiceStatus -ServiceName $ACPServiceName -StartType $script:ClientSettings.ACPServiceStartType -Status Running){
                        Write-CHLog -Function 'Invoke-CHACPInstall' -Message ('Installation of {0} Client has completed successfully.' -f $ACPServiceName)
                    
                        #Write PFE Status to Registry
                        Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_ACPStatus' -Data 'Healthy' -DataType string
                        Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastDate' -Data (Get-Date -format yyyy-MM-dd) -DataType string
                        Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastTime' -Data (Get-Date -format HH:mm:ss) -DataType string

                        Return $True
                    }
                    Else{
                        Write-CHLog -Function 'Invoke-CHACPInstall' -Message ('ERROR - Installation of {0} client completed, but could not start the service.' -f $ACPServiceName)
                    
                        #Write PFE Status to Registry
                        Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_ACPStatus' -Data 'UnHealthy' -DataType string
                        Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastDate' -Data (Get-Date -format yyyy-MM-dd) -DataType string
                        Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastTime' -Data (Get-Date -format HH:mm:ss) -DataType string

                        Return $False
                    }
                }
            }
            Else{
                Write-CHLog -Function 'Invoke-CHACPInstall' -Message ('ERROR - Installation of {0} Client has failed.' -f $ACPServiceName)

                #Write PFE Status to Registry
                Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_ACPStatus' -Data 'UnHealthy' -DataType string
                Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastDate' -Data (Get-Date -format yyyy-MM-dd) -DataType string
                Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastTime' -Data (Get-Date -format HH:mm:ss) -DataType string

                Return $False
            }
        }
        Catch{
            #Get first line of error only
            [string]$ErrorMsg = ($Error[0].toString()).Split('.')[0]

            #Catch any error and write tolog
            Write-CHLog -Function 'Invoke-CHACPInstall' -Message ('ERROR - {0}' -f $ErrorMsg)

            #Write PFE Status to Registry
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_ACPStatus' -Data 'UnHealthy' -DataType string
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastDate' -Data (Get-Date -format yyyy-MM-dd) -DataType string
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastTime' -Data (Get-Date -format HH:mm:ss) -DataType string

            Return $False
        }
    }
    else{
        Write-CHLog -Function 'Invoke-CHACPInstall' -Message 'WARNING - Remediation disabled'
        Write-CHLog -Function 'Invoke-CHACPInstall' -Message ('WARNING - {0} will not be repaired' -f $ACPServiceName)
    }
}

Function Send-CHHttpXML()
{
    <#
    .SYNOPSIS
    Uses HTTP to upload the XML created by the script to a WebService
    
    .DESCRIPTION
     Uses HTTP to upload the XML created by the script to a WebService.  The server the XML will be updloaded to will be the one located in HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft PFE Remediation for Configuration Manager\PrimarySiteName.
     Will return a bool value when complete.
    
    .EXAMPLE
    Send-CHHttpXML -XMLFile C:\test.xml -SiteServer HTTP:\\Primary01.contoso.local

    .PARAMETER XMLFile
    String value. Full path to the XML File.

    .PARAMETER SiteServer
    String value. Name of the Site Server with the installed webservice to upload the XML file to.

    .DEPENDENT FUNCTIONS
    Write-CHLog
    Get-CHServiceStatus
    Set-CHServiceStatus
    Set-CHRegistryValue

     #>

    PARAM
    (
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True)][string]$XMLFile,
        [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True)][string]$SiteServer
    )

    #Clear any errors
    $Error.Clear()
    
    If( $(Get-ChildItem -Path $XMLFile).Extension.ToUpper() -eq '.XML')
    {
        Write-CHLog -Function 'Send-CHHttpXML' -Message ('Received File {0} for http upload.' -f $XMLFile)
        Write-CHLog -Function 'Send-CHHttpXML' -Message 'Will check for Primary Site URL Override.'    
        
        #Check for Primary Site in Registry and use this value, otherwise use the one passed on commandline
        [string]$PrimarySiteServer = Get-CHRegistryValue -RegKey $script:PFEKeyPath  -RegValue 'PrimarySiteName'

        If(($PrimarySiteServer -eq 'Error') -or ($PrimarySiteServer -eq ''))
        {
            
            Write-CHLog -Function 'Send-CHHttpXML' -Message ('No override found, will attempt to upload XML to {0}' -f $SiteServer) 
            
            #Set WebService URL
            [string]$WebServiceURL = ('{0}/PFEIncoming/PFEIncoming.aspx' -f $SiteServer)
        }
        Else
        {
            
            Write-CHLog -Function 'Send-CHHttpXML' -Message ('HTTPUpload(): Override found, switching to upload XML to {0}' -f $PrimarySiteServer)

            #Set WebService URL
            [string]$WebServiceURL = ('{0}/PFEIncoming/PFEIncoming.aspx' -f $PrimarySiteServer)

        }

        #Check to make sure the XML file is where it should be
        If(Test-Path -Path $XMLFile)
        {
            Try
            {
                Write-CHLog -Function 'Send-CHHttpXML' -Message 'Sending XML to webservice' 
                
                #Get the Content of the XML
                #$content = Get-Content -Path "$XMLFile"
                [byte[]]$encodedContent = get-content -Encoding byte -Path ('{0}' -f $XMLFile) 

                #Create the Web Request                 
                $webRequest = [Net.WebRequest]::Create($WebServiceURL)
                #$encodedContent = [System.Text.Encoding]::UTF8.GetBytes($content)
                $webRequest.Method = 'POST'

                #encode the message
                if($encodedContent.length -gt 0)
                {
                    $webRequest.ContentLength = $encodedContent.length
                    $requestStream = $webRequest.GetRequestStream()
                    $requestStream.Write($encodedContent, 0, $encodedContent.length)
                    $requestStream.Close()
                }
  
                Write-CHLog -Function 'Send-CHHttpXML' -Message ('XML was sent to {0}.' -f $WebServiceURL)
                
                #Rename old XML file
                Remove-Item $XMLFile.Replace('xml','txt') -Force -ErrorAction SilentlyContinue
                Rename-Item $XMLFile -NewName $XMLFile.Replace('xml','txt').ToLower() -Force

                Return $True
            }
            Catch
            {
                [string]$ErrorMsg = ($Error[0].toString()).Split('.')[0]
                #Catch any error and write tolog
                Write-CHLog -Function 'Send-CHHttpXML' -Message ('ERROR - Failed to upload XML with error ({0})' -f $ErrorMsg)

                Return $False
            }
        }
        Else
        {
            Write-CHLog -Function 'Send-CHHttpXML' -Message ('ERROR - The file {0} is not found.' -f $XMLFile)

            Return $False
        }
    }
    Else
    {
        Write-CHLog -Function 'Send-CHHttpXML' -Message ('WARNING - The file {0} is not a XML.  Will not upload.' -f $XMLFile)

        Return $False
    }
}

Function Clear-BITSQueue()
{
    <#
    .SYNOPSIS
    Clears errors from the BITS Queue.

    .DESCRIPTION
    Gathers all the BITS Queues from all users, and clears errors from the Queue.
    Dependent on Write-CHLog

    .EXAMPLE
    Clear-BITSQueue

    .EXAMPLE
    Clear-BITSQueue -logonly

    .PARAMETER logonly
    This switch logs errors only.

    #>
    
    [CmdletBinding()]
    param
    (
        [switch]$logonly

    )

    Begin 
    {
        Import-Module -Name BITSTransfer -ErrorAction SilentlyContinue
    }

    Process
    {
        #Gathering any errors in the BITS queue
        $BITS = Get-BitsTransfer -AllUsers | Where-Object { ($_.JobState -like 'TransientError') -or ($_.JobState -like 'Error') }

        SWITCH ($logonly)
        {

            $true
            {
                IF ($BITS)
                {
                    Foreach ( $Job in $BITS) 
                    {
                        Write-CHLog -Function 'Clear-BITSQueue' -Message ('BITS Job currently in Queue : {0}' -f [string]::Join(' ', @($($Job.JobID; $Job.DisplayName, $Job.JobState))))
                    }

                }
                ELSE
                {
                    Write-CHLog -Function 'Clear-BITSQueue' -Message 'BITS Queue is empty.'
                }
            }
            $false
            {
                IF ($BITS)
                {
                    Foreach ( $Job in $BITS) 
                    {
                        Write-CHLog -Function 'Clear-BITSQueue' -Message ('BITS Job to be removed : {0}' -f [string]::Join(' ', @($($Job.JobID; $Job.DisplayName, $Job.JobState))))
                        Try
                        {
                            Get-BitsTransfer -AllUsers | Where-Object { ($_.JobState -like 'TransientError') -or ($_.JobState -like 'Error') } | Remove-BitsTransfer
                        }
                        Catch
                        {
                            $RegRead = 'Error'
                            $ErrorMsg = ($Error[0].toString()).Split('.')[0]
                            Write-CHLog -Function 'Clear-BITSQueue' -Message 'Unable to remove BITS Errors'
                            Write-CHLog -Function 'Clear-BITSQueue' -Message ('{0}' -f $ErrorMsg)
                        }
                    }
                }
                ELSE
                {
                    Write-CHLog -Function 'Clear-BITSQueue' -Message 'Remediate: BITS Queue is empty.'
                }

            }
        }

        $BITSRecheck = Get-BitsTransfer -AllUsers | Where-Object { ($_.JobState -like 'TransientError') -or ($_.JobState -like 'Error') }
        #Checking for backlogged BITS jobs and logonly enabled = Unhealthy
        if ($BITS -and $logonly) {$return = $false}
        
        #Checking for no backlogged BITS jobs and logonly enabled = Healthy
        if (!$BITS -and $logonly) {$return = $true}
         
        #Checking for no backlogged BITS jobs and logonly disabled = Healthy
        if ((!$BITSRecheck) -and (!$logonly)) {$return = $true}

        #Checking for no backlogged BITS jobs and logonly disabled = Healthy
        if (($BITSRecheck) -and (!$logonly)) {$return = $false}
        
    }

    End
    {
        return $return
    }

}

Function Write-CHEventLog()
{
    <#
    .SYNOPSIS
    Writes events to the Windows Event Log.

    .DESCRIPTION
    Designed to write specific events to the Windows Event log.
    --NOTE: EventIDs to take note.

    65000 Information == General Information during the Script
    65001 Error == Any Errors during the Script
    65002 NoRemediation == Any action taken as a result of remediation not being enabled
    65003 Remediation ==  Any action taken as a result of remediation being enabled
    
    .EXAMPLE
    Write-CHEventLog -Function "Main" -Message "Some Message" -IDType Info -Enabled $true

    .EXAMPLE
    Write-CHEventLog -Function "Main" -Message "Some Message" -IDType Error -Enabled $global:ClientSettings.EventLog 

    .PARAMETER Function
    The function that called for Write-CHEventLog.

    .PARAMETER Message
    The content of the message to be logged.
    
    .PARAMETER Source
    The Source sets the logging source for centralized management and identification.
    --NOTE: Not recommended to change once deployed.
    --NOTE: The Source is set after the client settings are imported, in the global variables region.
    
    .PARAMETER IDType
    IDType sets the related custom event IDs for the type of action or result.

    .PARAMETER Enabled
    Accepts argument from $global:ClientSettings to determine if the Function is enabled. 
       
    #>
    
    param
    (
        [Parameter(Mandatory=$True)][string]$Function,
        [Parameter(Mandatory=$True)][string]$Message,
        [string]$Source = 'PFE Client Remediation Script',
        [Parameter(Mandatory=$True)][ValidateSet('Info','Error','Remediation','NoRemediation')][String]$IDType,
        [Parameter(Mandatory=$True)][string]$Enabled
    )

    Begin 
    {
        Switch ($IDType)
        {
            'Info'          {[int]$ID = 65000 } #Information
            'Error'         {[int]$ID = 65001 } #Error
            'Remediation'   {[int]$ID = 65002 } #NoRemediation
            'NoRemediation' {[int]$ID = 65003 } #Remediation
        }
    }

    Process
    {
        #define output to log file    
        [string]$Output = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss:ff') + ' - ' + $Function + '(): ' + $Message

        Try
        {
            If ($Enabled -eq $true)
            {
                Switch ($IDType)
                {
                    'Info'          {Write-EventLog -Source $Source -LogName Application -EntryType Information -EventId $ID -Message $Output } 
                    'Error'         {Write-EventLog -Source $Source -LogName Application -EntryType Error -EventId $ID -Message $Output } 
                    'Remediation'   {Write-EventLog -Source $Source -LogName Application -EntryType Information -EventId $ID -Message $Output } 
                    'NoRemediation' {Write-EventLog -Source $Source -LogName Application -EntryType Warning -EventId $ID -Message $Output } 
                }
            }
        }
        Catch
        {
            'Cannot write to event log; exiting script'
            Exit(1)
        }
    }

    End
    {

    }
}

#region Get-PFESiteAssignment
Function Get-PFESiteAssignment
{
	<#
			Created on:   	05.08.2017 00:43
			Created by:   	Mieszko Ślusarczyk
			Version:		1.0
    .SYNOPSIS
    Get SCCM PFE Remediation Agent Server name.
    
    .DESCRIPTION
	The script will read the primary SCCM site currently assigned to SCCM PFE Remediation Agent from registry and display it's FQDN

    
    .EXAMPLE
    Get-PFESiteAssignment

    .DEPENDENT FUNCTIONS
    Write-CHLog

    #>
	If (Test-Path "HKLM:\SOFTWARE\Microsoft\Microsoft PFE Remediation for Configuration Manager")
	{
		Try
		{
			$PFEServer = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft PFE Remediation for Configuration Manager").PrimarySiteName
			If ($PFEServer)
			{
				If ($global:blnDebug) { Write-CHLog -strFunction "Get-PFESiteAssignment" -strMessage "Info: PFE server name is $PFEServer" }
			}
			Else
			{
				Write-CHLog -strFunction "Get-PFESiteAssignment" -strMessage "Error: Could not get PFE server name"
			}
		}
		Catch
		{
			Write-CHLog -strFunction "Get-PFESiteAssignment" -strMessage "Error: Could not get PFE server name"
		}
	}
	Else
	{
		Write-CHLog -strFunction "Get-PFESiteAssignment" -strMessage "Error: `"HKLM:\SOFTWARE\Microsoft\Microsoft PFE Remediation for Configuration Manager`" does not exist"
	}
	Return $PFEServer
}#endregion Get-PFESiteAssignment

#region Set-PFESiteAssignment
Function Set-PFESiteAssignment
{
	<#
		#	Created on:   	08.08.2017 14:00
		#	Created by:   	Mieszko Ślusarczyk
    .SYNOPSIS
    Set SCCM PFE Remediation Agent Server name.
    
    .DESCRIPTION
	The script will assign PFE Remediation Agent with SCCM primary site and display it's FQDN

    
    .EXAMPLE
    Set-PFESiteAssignment

    .DEPENDENT FUNCTIONS
    Write-CHLog

    #>
	$PrimarySiteServer = Get-SMSMP -Source AD -Primary $true
	If ($PrimarySiteServer)
	{
		If (Test-Path "HKLM:\SOFTWARE\Microsoft\Microsoft PFE Remediation for Configuration Manager")
		{
			Try
			{
				
				Write-CHLog -strMessage "Info: Setting PFE server name to $PrimarySiteServer" -strFunction Set-PFESiteAssignment
				Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft PFE Remediation for Configuration Manager" -Name PrimarySiteName -Value "$PrimarySiteServer"
				Try
				{
					Write-CHLog -strMessage "Info: PFE server name changed, restarting PFERemediation service" -strFunction Set-PFESiteAssignment
					Restart-Service PFERemediation
				}
				Catch
				{
					Write-CHLog -strMessage "Error: Failed restart PFERemediation service" -strFunction Set-PFESiteAssignment
				}
			}
			Catch
			{
				Write-CHLog -strMessage "Error: Failed to set PFE server name to $PrimarySiteServer" -strFunction Set-PFESiteAssignment
			}
		}
		Else
		{
			Write-CHLog -strMessage "Error: `"HKLM:\SOFTWARE\Microsoft\Microsoft PFE Remediation for Configuration Manager`" does not exist." -strFunction Set-PFESiteAssignment
		}
	}
	Else
	{
		Write-CHLog -strMessage "Error: No Primary Site Server FQDN detected" -strFunction Set-PFESiteAssignment
	}
}#endregion Set-PFESiteAssignment

#region Get-AllDomains
Function Get-AllDomains
{
	<#
			Created on:   	08.08.2017 11:55
			Created by:   	Mieszko Ślusarczyk
			Version:		1.0
    .SYNOPSIS
    Gets all domains in a forest.
    
    .DESCRIPTION
	The script gets all the domains in the forest and returns them as $domains

    
    .EXAMPLE
    Get-AllDomains

    #>
	$Root = [ADSI]"LDAP://RootDSE"
	$oForestConfig = $Root.Get("configurationNamingContext")
	$oSearchRoot = [ADSI]("LDAP://CN=Partitions," + $oForestConfig)
	$AdSearcher = [adsisearcher]"(&(objectcategory=crossref)(netbiosname=*))"
	$AdSearcher.SearchRoot = $oSearchRoot
	$domains = $AdSearcher.FindAll()
	return $domains
}#endregion Get-AllDomains

#region Get-ADSite
function Get-ADSite
{
	<#
			Created on:   	08.08.2017 12:02
			Created by:   	Mieszko Ślusarczyk
			Version:		1.0
    .SYNOPSIS
    Gets AD site for computer
    
    .DESCRIPTION
	The script gets the current AD site for computer - if no computer is specified it uses $env:COMPUTERNAME

    
    .EXAMPLE
    Get-ADSite
	Get-ADSite COMPUTERNAME

    .DEPENDENT FUNCTIONS
    Write-CHLog

    #>
	param
	(
		$ComputerName = $env:COMPUTERNAME
	)
	Try
	{
		If ($global:blnDebug) {Write-CHLog -strMessage "Info: trying to extract site code using System.DirectoryServices.ActiveDirectory.ActiveDirectorySite" -strFunction Get-ADSite }
		$ADSite = ([System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite()).Name
	}
	Catch
	{
		Write-CHLog -strMessage "Warning: could not extract site code using System.DirectoryServices.ActiveDirectory.ActiveDirectorySite, trying nltest" -strFunction Get-ADSite
		If (!($ComputerName))
		{
			Write-CHLog -strMessage "Error: Computer Name not passed" -strFunction Get-ADSite
		}
		$site = nltest /server:$ComputerName /dsgetsite 2>$null
		if ($LASTEXITCODE -eq 0) { $ADSite = $site[0] }
	}
	If ($ADSite)
	{
		If ($global:blnDebug){ Write-CHLog -strMessage "Info: AD Site Name is $ADSite" -strFunction Get-ADSite }
	}
	Else
	{
		Write-CHLog -strMessage "Error: Failed to find AD Site Name" -strFunction Get-ADSite
	}
	$ADSite
}#endregion Get-ADSite

#region Get-SMSSiteCode
Function Get-SMSSiteCode
{
	<#
			Created on:   	08.08.2017 12:07
			Created by:   	Mieszko Ślusarczyk
			Version:		1.0
    .SYNOPSIS
    Gets SCCM Site code for the current computer or AD Site
    
    .DESCRIPTION
	Gets SCCM Site code for the current computer (if used with WMI source) or AD Site reveived from Get-ADSite

    
    .EXAMPLE
    Get-SMSSiteCode
	Get-SMSSiteCode -Source WMI -Primary $false
	Get-SMSSiteCode -Primary $false

    .DEPENDENT FUNCTIONS
	Get-ADSite
	Get-AllDomains
	Write-CHLog

    #>
	param
	(
		[ValidateSet('AD', 'WMI')]
		[string]$Source = "AD",
		[bool]$Primary = $true
	)
	
	If ($Source -eq "AD")
	{
		If ($Primary -eq $true)
		{
			$SMSSiteCode = Get-SMSSiteCode -Source AD -Primary $false
			If ($SMSSiteCode)
			{
				Try
				{
					If ($global:blnDebug) { Write-CHLog -strMessage "Debug: Looking for $SMSSiteCode in $($Domain.Properties.ncname[0])" -strFunction Get-SMSSiteCode }
					$ADSysMgmtContainer = [ADSI]("LDAP://CN=System Management,CN=System," + "$($Domain.Properties.ncname[0])")
					$AdSearcher = [adsisearcher]"(&(mSSMSSiteCode=$SMSSiteCode)(ObjectClass=mSSMSSite))"
					$AdSearcher.SearchRoot = $ADSysMgmtContainer
					$CMSiteFromAD = $AdSearcher.FindONE()
					$SMSPrimarySiteCode = $CMSiteFromAD.Properties.mssmsassignmentsitecode
					If ($SMSPrimarySiteCode)
					{
						If ($global:blnDebug){ Write-CHLog -strMessage "Success: Found SCCM primary site code $SMSPrimarySiteCode in AD" -strFunction Get-SMSSiteCode }
						$SMSSiteCode = $SMSPrimarySiteCode
					}
					Else
					{
						Write-CHLog -strMessage "Error: Could not find SCCM primary site code" -strFunction Get-SMSSiteCode
					}
				}
				Catch
				{
					Write-CHLog -strMessage "Error: Failed to find SCCM primary site code" -strFunction Get-SMSSiteCode
				}
			}
			Else
			{
				Write-CHLog -strMessage "Error: Get-SMSSiteCode did not return SMSSiteCode" -strFunction Get-SMSSiteCode
			}
			
			Return $SMSSiteCode
		}
		ElseIf ($Primary -eq $false)
		{
			$domains = Get-AllDomains
			$ADSite = Get-ADSite
			Foreach ($script:domain in $domains)
			{
				Try
				{
					If ($global:blnDebug){ Write-CHLog -strMessage "Looking for $ADSite in $($Domain.Properties.ncname[0])" -strFunction Get-SMSSiteCode }
					$ADSysMgmtContainer = [ADSI]("LDAP://CN=System Management,CN=System," + "$($Domain.Properties.ncname[0])")
					$AdSearcher = [adsisearcher]"(&(mSSMSRoamingBoundaries=$ADSite)(ObjectClass=mSSMSSite))"
					$AdSearcher.SearchRoot = $ADSysMgmtContainer
					$CMSiteFromAD = $AdSearcher.FindONE()
					$SMSSiteCode = $CMSiteFromAD.Properties.mssmssitecode
					If ($SMSSiteCode)
					{
						If ($global:blnDebug){ Write-CHLog -strMessage "Success: Found SCCM site code $SMSSiteCode" -strFunction Get-SMSSiteCode }
						Break
					}
				}
				Catch { }
			}
			Return $SMSSiteCode
		}
	}
	ElseIf ($Source -eq "WMI")
	{
		If ($Primary -eq $true)
		{
			Try
			{
				If ($global:blnDebug){ Write-CHLog -strMessage "Info: Trying to get primary site code assignment from WMI" -strFunction Get-SMSSiteCode }
				Try
				{
					$SMSPrimarySiteCode = ([wmiclass]"ROOT\ccm:SMS_Client").GetAssignedSite().sSiteCode
				}
				Catch
				{
					Write-CHLog -strMessage "Error: Failed to get primary site code assignment from WMI" -strFunction Get-SMSSiteCode
				}
				
				If ($SMSPrimarySiteCode)
				{
					If ($global:blnDebug)
					{ Write-CHLog -strMessage "Success: Found SCCM primary site code in WMI $SMSPrimarySiteCode" -strFunction Get-SMSSiteCode }
					$SMSSiteCode = $SMSPrimarySiteCode
				}
				Else
				{
					Write-CHLog -strMessage "Error: Failed to get primary site code assignment from WMI" -strFunction Get-SMSSiteCode
				}
			}
			Catch
			{
				Write-CHLog -strMessage "Error: Failed to get primary site code assignment from WMI" -strFunction Get-SMSSiteCode
			}
			Return $SMSSiteCode
		}
		ElseIf ($Primary -eq $false)
		{
			Try
			{
				If ($global:blnDebug)
				{ Write-CHLog -strMessage "Info: Trying to get site code assignment from WMI" -strFunction Get-SMSSiteCode }
				$SMSSiteCode = Get-WmiObject -Namespace "ROOT\ccm" -Class "SMS_MPProxyInformation" -Property SiteCode | select -ExpandProperty SiteCode
				If ($SMSSiteCode)
				{
					If ($global:blnDebug)
					{ Write-CHLog -strMessage "Success: Found SCCM site code in WMI $SMSSiteCode" -strFunction Get-SMSSiteCode }
				}
			}
			Catch
			{
				Write-CHLog -strMessage "Error: Failed to get primary site code assignment from WMI" -strFunction Get-SMSSiteCode
			}
		}
	}
	
	If ($Primary -eq $true)
	{
		$SMSSiteCode = $SMSPrimarySiteCode
	}
}#endregion Get-SMSSiteCode

#region Set-SMSSiteCode
function Set-SMSSiteCode
{
	<#
			Created on:   	08.08.2017 12:07
			Created by:   	Mieszko Ślusarczyk
			Version:		1.0
    .SYNOPSIS
    Sets SCCM Site code assignment for the current computer
    
    .DESCRIPTION
	Automatically sets SCCM Site code assignment for the current computer 

    
    .EXAMPLE
    Set-SMSSiteCode

    .DEPENDENT FUNCTIONS
	Get-SMSSiteCode
	Write-CHLog

    #>
	param
	(
		[bool]$Auto = $true
	)
	If ($Auto)
	{
		Try
		{
			$SMS_Client = ([wmi]"ROOT\ccm:SMS_Client=@")
			$SMS_Client.EnableAutoAssignment = $True
			$SMS_Client.Put()
			
			Restart-Service 'CcmExec'
		}
		Catch
		{
			Write-CHLog -strMessage "Error: Failed to automatically assign SCCM site" -strFunction Set-SMSSiteCode
		}
        Write-CHLog -strMessage "Info: Waiting 120 seconds before trying to read the assignment" -strFunction Set-SMSSiteCode
        Start-Sleep -Seconds 120
		$SMSSiteCode = Get-SMSSiteCode -Source WMI -Primary $true
		If ($SMSSiteCode)
		{
			Write-CHLog -strMessage "Info: Automatically assigned to SCCM site $SMSSiteCode" -strFunction Set-SMSSiteCode
		}
		Else
		{
			Write-CHLog -strMessage "Error: Failed to automatically assign SCCM site" -strFunction Set-SMSSiteCode
		}
	}
}#endregion Set-SMSSiteCode

#region Get-SMSMP
Function Get-SMSMP
{
	<#
			Created on:   	08.08.2017 12:07
			Created by:   	Mieszko Ślusarczyk
			Version:		1.0
    .SYNOPSIS
    Gets SCCM management point for the current computer or AD Site
    
    .DESCRIPTION
	Gets SCCM management point for the current computer (if used with WMI source) or AD Site reveived from Get-ADSite

    
    .EXAMPLE
    Get-SMSMP
	Get-SMSMP -Source WMI -Primary $false
	Get-SMSMP -Primary $false

    .DEPENDENT FUNCTIONS
	Get-ADSite
	Get-AllDomains
	Write-CHLog

    #>
	param
	(
		[ValidateSet('AD', 'WMI')]
		[string]$Source = "AD",
		[bool]$Primary = $true
	)
	If ($Source -eq "AD")
	{
		If ($Primary -eq $true)
		{
			$SMSSiteCode = Get-SMSSiteCode -Source AD -Primary $true
			[string]$SMSMPType = "Primary Site Management Point"
		}
		ElseIf ($Primary -eq $false)
		{
			$SMSSiteCode = Get-SMSSiteCode -Source AD -Primary $false
			[string]$SMSMPType = "Management Point"
		}
		
		If ($SMSSiteCode)
		{
			If ($global:blnDebug){ Write-CHLog -strMessage "Info: Trying to find SCCM $SMSMPType in AD" -strFunction Get-SMSMP }
			Try
			{
				$ADSysMgmtContainer = [ADSI]("LDAP://CN=System Management,CN=System," + "$($Domain.Properties.ncname[0])")
				$AdSearcher = [adsisearcher]"(&(Name=SMS-MP-$SMSSiteCode-*)(objectClass=mSSMSManagementPoint))"
				$AdSearcher.SearchRoot = $ADSysMgmtContainer
				$CMManagementPointFromAD = $AdSearcher.FindONE()
				$MP = $CMManagementPointFromAD.Properties.mssmsmpname[0]
				If ($MP)
				{
					If ($global:blnDebug) {Write-CHLog -strMessage "Success: Found SCCM $SMSMPType $MP in AD" -strFunction Get-SMSMP }
				}
				Else
				{
					Write-CHLog -strMessage "Error: Failed to find SCCM $SMSMPType in AD" -strFunction Get-SMSMP
				}
			}
			Catch
			{
				Write-CHLog -strMessage "Error: Failed to find SCCM $SMSMPType in AD" -strFunction Get-SMSMP
			}
			Return $MP
		}
		Else
		{
			Write-CHLog -strMessage "Error: Get-SMSSiteCode did not return SMSPrimarySiteCode" -strFunction Get-SMSMP
		}
	}
	ElseIf ($Source -eq "WMI")
	{
		If ($Primary -eq $true)
		{
			[string]$SMSMPType = "Primary Site Management Point"
		}
		ElseIf ($Primary -eq $false)
		{
			[string]$SMSMPType = "Management Point"
		}
		If ($global:blnDebug)
		{
			Write-CHLog -strMessage "Info: Trying to find SCCM $SMSMPType in WMI" -strFunction Get-SMSMP
			
			Try
			{
				If ($Primary -eq $true)
				{
					$MP = Get-WmiObject -Namespace "ROOT\ccm" -Class "SMS_LookupMP" -Property Name | select -ExpandProperty Name
				}
				ElseIf ($Primary -eq $false)
				{
					$MP = Get-WmiObject -Namespace "ROOT\ccm" -Class "SMS_LocalMP" -Property Name | select -ExpandProperty Name
				}
				If ($MP)
				{
					Write-CHLog -strMessage "Success: SCCM $SMSMPType in WMI is $MP" -strFunction Get-SMSMP
				}
				Else
				{
					Write-CHLog -strMessage "Info: Failed to find SCCM $SMSMPType in WMI" -strFunction Get-SMSMP
				}
			}
			Catch
			{
				Write-CHLog -strMessage "Info: Failed to find SCCM $SMSMPType in WMI" -strFunction Get-SMSMP
			}
		}
		Return $MP
	}
	Return $MP
}#endregion Get-SMSMP

#region Test-SMSAssignedSite
function Test-SMSAssignedSite
{
	Write-CHLog -strMessage "Info: Checking SCCM client assignment" -strFunction Test-SMSAssignedSite
	[string]$SMSSiteCodeWMI = Get-SMSSiteCode -Source WMI -Primary $true
	If ($SMSSiteCodeWMI)
	{
		[string]$SMSSiteCodeAD = Get-SMSSiteCode -Source AD -Primary $true
		If ("$SMSSiteCodeAD" -eq "$SMSSiteCodeWMI")
		{
			Write-CHLog -strMessage "Info: SCCM client assignment is up to date ($SMSSiteCodeWMI)" -strFunction Test-SMSAssignedSite
		}
		Else
		{
			Write-CHLog -strMessage "Warning: SCCM Site Code in WMI: $SMSSiteCodeWMI in AD: $SMSSiteCodeAD " -strFunction Test-SMSAssignedSite
			Write-CHLog -strMessage "Warning: SCCM client assignment is NOT up to date, trying to automatically set it" -strFunction Test-SMSAssignedSite
            Set-SMSSiteCode
		}
	}
	Else
	{
		Write-CHLog -strMessage "Warning: SCCM client couldn't read SCCM site assignment, trying to automatically set it" -strFunction Test-SMSAssignedSite
		Set-SMSSiteCode
	}
}#endregion Test-SMSAssignedSite

#region Test-PFEAssignedSite
function Test-PFEAssignedSite
{
	Write-CHLog -strMessage "Info: Checking PFE agent assignment" -strFunction Test-SMSAssignedSite
	[string]$PFESiteAssignment = Get-PFESiteAssignment
	[string]$SMSMP = Get-SMSMP -Source AD -Primary $true
	If ($PFESiteAssignment)
	{
		If ($PFESiteAssignment -eq $SMSMP)
		{
			Write-CHLog -strMessage "Info: PFE agent assignment is up to date ($PFESiteAssignment)" -strFunction Test-PFEAssignedSite
		}
		Else
		{
			Write-CHLog -strMessage "Warning: PFE agent assignment is: $PFESiteAssignment, SCCM Primary Management point is $SMSMP" -strFunction Test-PFEAssignedSite
			Write-CHLog -strMessage "Warning: PFE agent assignment is NOT up to date trying to automatically set it" -strFunction Test-PFEAssignedSite
			Set-PFESiteAssignment
		}
	}
	Else
	{
		Write-CHLog -strMessage "Warning: PFE agent couldn't read site assignment, trying to automatically set it" -strFunction Test-PFEAssignedSite
		Set-PFESiteAssignment
	}
}#endregion Test-PFEAssignedSite

#endregion #################################### END FUNCTIONS ####################################>

#region #################################### START GLOBAL VARIABLES ####################################>

#get relative path to script running location
#the full path includes the name of the script; removing it by replacing the name with empty
[string]$script:CurrentLocation = ($MyInvocation.MyCommand.Path).Replace(('\{0}' -f $MyInvocation.MyCommand.Name),'')

Write-CHLog -Function 'Main' -Message 'PFE Client Remediation Script Started'

[string]$script:PFEKeyPath = 'HKLM:\software\Microsoft\Microsoft PFE Remediation for Configuration Manager'

#get OS Name and Version
[string]$OSName = Get-CHRegistryValue -RegKey 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -RegValue 'ProductName'
[string]$script:OSVersion = Get-CHRegistryValue -RegKey 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -RegValue 'CurrentVersion'

#set OS Type using OS Name
if (($OSName.toLower()).Contains('server')){ [string]$script:OSType = 'server' }
else { [string]$script:OSType = 'workstation' }

#get client settings from XML file
Try
{
    [xml]$xmlUserData = Get-Content -Path ('{0}\PFERemediationSettings.xml' -f $script:CurrentLocation) -ErrorAction Stop
    Write-CHLog -Function 'Main.Globals' -Message 'XML file found: gathering settings'

    if ($script:OSType -eq 'workstation')
    {
        $XMLSettingsData = New-Object -TypeName PSObject
        Foreach ($Element in $xmlUserData.sites.default.workstation.ChildNodes )
        {
            $XMLSettingsData | Add-Member -MemberType noteproperty -Name $Element.Name -Value $Element.'#text' -ErrorAction SilentlyContinue
	      }
        
        $null = $xmlUserData.sites.default.RemoveChild($xmlUserData.sites.default.server)
        $null = $xmlUserData.sites.default.RemoveChild($xmlUserData.sites.default.workstation)

        Foreach ($Element in $xmlUserData.sites.default.ChildNodes )
        {
            $XMLSettingsData | Add-Member -MemberType noteproperty -Name $Element.Name -Value $Element.'#text' -ErrorAction SilentlyContinue
	      }

        [object]$script:ClientSettings = $XMLSettingsData
    }

    if ($script:OSType -eq 'server')
    {
        
        $XMLSettingsData = New-Object -TypeName PSObject
        Foreach ($Element in $xmlUserData.sites.default.Server.ChildNodes )
        {
            $XMLSettingsData | Add-Member -MemberType noteproperty -Name $Element.Name -Value $Element.'#text' -ErrorAction SilentlyContinue
	      }
        
        $null = $xmlUserData.sites.default.RemoveChild($xmlUserData.sites.default.server)
        $null = $xmlUserData.sites.default.RemoveChild($xmlUserData.sites.default.workstation)

        Foreach ($Element in $xmlUserData.sites.default.ChildNodes )
        {
            $XMLSettingsData | Add-Member -MemberType noteproperty -Name $Element.Name -Value $Element.'#text' -ErrorAction SilentlyContinue
	      }

        [object]$script:ClientSettings = $XMLSettingsData
       
    }

    [bool]$script:Debug = [Convert]::ToBoolean($script:ClientSettings.Debug)
}
Catch
{
    Write-CHLog -Function 'Main.Globals' -Message 'XML file not found: exiting script'
    ('Log file location: {0}; exiting script as customer settings XML file is missing' -f $LogFile)
    
    #exiting with generic exit code; more logic is required for exit code that has meaning
    Exit(2)
}

# Setting Windows Event Log Source for Script if Enabled.
if ($script:ClientSettings.EventLog -eq $true)
{
    New-EventLog -Source 'PFE Client Remediation Script' -LogName Application -ErrorAction SilentlyContinue
}

Write-CHEventLog -Function 'Main' -Message 'PFE Client Remediation Script Started' -IDType Info -Enabled $script:ClientSettings.EventLog

#get SCCM assigned sitecode and version
[string]$script:SiteCode = Get-CHRegistryValue -RegKey 'HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client' -RegValue 'AssignedSiteCode' 
[string]$SCCMVersion = Get-CHRegistryValue -RegKey 'HKLM:\software\microsoft\sms\mobile client' -RegValue 'ProductVersion'

If ($script:SiteCode -eq 'Error') {$script:SiteCode = $script:ClientSettings.Sitecode}
If ($SCCMVersion -eq 'Error') {$SCCMVersion = '0'}

Write-CHLog -Function 'Main.Globals' -Message ('Using SiteCode {0}.' -f $script:SiteCode)
Write-CHLog -Function 'Main.Globals' -Message ('Current SCCM Version {0}.' -f $SCCMVersion)



if($SCCMVersion.StartsWith('4'))
{
    if($script:ClientSettings.RemediateOld2007Client -eq $False)
    {
        Write-CHLog -Function 'Main.Globals' -Message 'Error - SCCM 2007 is not supported in this script; quitting script'
        Write-CHEventLog -Function 'Main.Globals' -Message 'Error - SCCM 2007 is not supported in this script; quitting script' -IDType Error -Enabled $script:ClientSettings.EventLog

        #exiting with generic exit code; more logic is required for exit code that has meaning
        Exit(2)
    }
    else
    {
        $script:SCCMInstalled = $False
    }
}
elseif($SCCMVersion.StartsWith('5'))
{
    $script:SCCMInstalled = $True
}
else
{
    $script:SCCMInstalled = $False
}

#check for OS version greater than 6 (Vista or higher)
if([int](($script:OSVersion).split('.',2)[0]) -lt 6)
{
    if([int](($script:OSVersion).split('.',2)[1]) -eq 0) #Check for Vista
    { 
        #Verify that if the OS is Vista that the PowerShell version is at least 2
        if((get-host).Version.Major -lt 2)
        {
            Write-CHLog -Function 'Main.Globals' -Message 'The minimum supported PowerShell version for this utility is 2.x; exiting script'
            Exit(3)
        }
    }
    
    Write-CHLog -Function 'Main.Globals' -Message 'The minimum supported Operating System for this utility is Vista; exiting script'
    Exit(3)
}



#endregion #################################### END GLOBAL VARIABLES ####################################>

#region #################################### START MAIN LOGIC ####################################>

#script needs to run as an administrator; no action will be taken if check for admin is false
if(([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator'))
{
    if((Get-Process -Name 'tsmanager' -ErrorAction SilentlyContinue) -eq $null)
    {
        Write-CHLog -Function 'Main' -Message 'Checking log file size'

        #if log file is over 5MB, rename the log
        if((Get-ChildItem -Path ('{0}\PS-PFERemediationScript.log' -f $script:CurrentLocation)).Length -gt 5242880)
        {
            Try
            {
                #remove the old .lo_ file if it exists and rename the large log file
                if(Test-Path -Path ('{0}\PS-PFERemediationScript.lo_' -f $script:CurrentLocation) -ErrorAction SilentlyContinue){ Remove-Item -Path ('{0}\PS-PFERemediationScript.lo_' -f $script:CurrentLocation) -ErrorAction Stop}
                Rename-Item -Path ('{0}\PS-PFERemediationScript.log' -f $script:CurrentLocation) -NewName ('{0}\PS-PFERemediationScript.lo_' -f $script:CurrentLocation) -Force -ErrorAction Stop
            }
            Catch
            {
                Write-CHLog -Function 'Main' -Message 'Error - Cannot rename log file'
                Write-CHEventLog -Function 'Main' -Message 'Error - Cannot rename log file' -IDType Error -Enabled $script:ClientSettings.EventLog
            }
        }
        

        
        [string]$AgentName = 'PFE Remediation'

        Write-CHLog -Function 'Main.PreCheck' -Message ('Script version is {0}' -f $global:ScriptVersion)

        #Initiate PFE Reboot Status
        $PFEReboot = 'False'
        
        ###############################################################################
        #   Check Registry Configuration
        ###############################################################################

        if($script:Debug) 
        { 
            Write-CHLog -Function 'Main.PreCheck' -Message 'Checking Microsoft PFE Remediation for Configuration Manager registry configuration' 
        }

        if(!(Test-Path -Path $script:PFEKeyPath))
        {
            #PFE registry keys do not exist yet; creating them
            [string]$RegKey = ($script:PFEKeyPath).Split('\')[3]
            [string]$RegPath = $script:PFEKeyPath.Replace(('\{0}' -f $RegKey),'')
            Try
            {
                $null = New-Item -Path $RegPath -Name $RegKey -ErrorAction Stop
            }
            Catch
            {
                Write-CHLog -Function 'Main.PreCheck' -Message 'Error: Cannot write registry key Microsoft PFE Remediation for Configuration Manager'
                Write-CHEventLog -Function 'Main.PreCheck' -Message 'Error: Cannot write registry key Microsoft PFE Remediation for Configuration Manager' -IDType Error -Enabled $script:ClientSettings.EventLog
            }
            
            #Set-CHRegistryValue $global:PFEKeyPath
            
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'Agent Site' -Data $script:SiteCode -DataType 'string'
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_WMIRebuildAttempts' -Data 0 -DataType 'dword'
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_RebootPending' -Data $PFEReboot -DataType 'string'
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_ClientInstallCount' -Data 0 -DataType 'dword'        
            #
            # Set-CHRegistryValue $script:PFEKeyPath 'PFE_LastAction' 'System Check' 'string'
            # 
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastDate' -Data (Get-Date -format yyyy-MM-dd) -DataType 'string'
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastTime' -Data (Get-Date -format HH:mm:ss) -DataType 'string'
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_ScriptVer' -Data $ScriptVersion -DataType 'string'
        }
        else
        {
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_ScriptVer' -Data $ScriptVersion -DataType 'string'
            
            if((Get-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_WMIRebuildAttempts') -eq '')
            {
                Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_WMIRebuildAttempts' -Data 0 -DataType 'dword'
            }
            if((Get-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_ClientInstallCount') -eq '')
            {
                Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_ClientInstallCount' -Data 0 -DataType 'dword'
            }
        }

        if($script:Debug) 
        { 
            Write-CHLog -Function 'Main.PreCheck' -Message 'Registry key configuration completed' 
        }

        <### END REGISTRY CHECK ###>

        ###############################################################################
        #   Write Remediation Flag 
        ###############################################################################
        if($script:OSType -eq 'workstation') 
        {
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_Remediation' -Data $script:ClientSettings.WorkstationRemediation -DataType 'string'
            Write-CHLog -Function 'Remediation.Flag' -Message ('Workstation Remedation has been set to {0}' -f $ClientSettings.WorkstationRemediation)
            Write-CHEventLog -Function 'Remediation.Flag' -Message ('Workstation Remedation has been set to {0}' -f $script:ClientSettings.WorkstationRemediation) -IDType Remediation -Enabled $script:ClientSettings.EventLog
        }

        if($script:OSType -eq 'server') 
        {
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_Remediation'  -Data $($script:ClientSettings.ServerRemediation) -DataType 'string'
            Write-CHLog -Function 'Remediation.Flag' -Message ('Server Remedation has been set to {0}' -f $($script:ClientSettings.ServerRemediation))
            Write-CHEventLog -Function 'Remediation.Flag' -Message ('Workstation Remedation has been set to {0}' -f $($script:ClientSettings.WorkstationRemediation)) -IDType Remediation -Enabled $script:ClientSettings.EventLog
        }

        #update status in registry
        #
        # Set-CHRegistryValue $script:PFEKeyPath -RegValue 'PFE_LastAction' -Data 'PFE Remediation Flag' -DataType 'string'
        #
        Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastDate' -Data (Get-Date -format yyyy-MM-dd) -DataType 'string'
        Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastTime' -Data (Get-Date -format HH:mm:ss) -DataType 'string'

        ###############################################################################
        #   Check Existing XML Files
        ###############################################################################

        Write-CHLog -Function 'Main.PreCheck' -Message 'Looking for existing XML and deleting file if found'
        
        if(Test-Path -Path ('{0}\{1}.xml' -f $script:CurrentLocation, $($env:COMPUTERNAME)))
        {
            Try
            { 
                $null = Remove-Item -Path ('{0}\{1}.xml' -f $script:CurrentLocation, $($env:COMPUTERNAME)) -ErrorAction Stop
                if($script:Debug) { Write-CHLog -Function 'Main.PreCheck' -Message 'Old XML deleted' }
            }
            Catch
            {
                Write-CHLog -Function 'Main.PreCheck' -Message 'Error: Failed to delete existing xml'
                Write-CHEventLog -Function 'Main.PreCheck' -Message 'Error: Failed to delete existing xml' -IDType Error -Enabled $script:ClientSettings.EventLog
            }
        }

        ###############################################################################
        #   Check Pending Reboots
        ###############################################################################

        $RebootPending = Get-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_RebootPending'

        if($RebootPending -eq $True)
        {
            if($script:Debug) 
            { 
                Write-CHLog -Function 'Main.RebootCheck' -Message 'Checking Reboot Status' 
            }

            [string]$LastReboot = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction SilentlyContinue | ForEach-Object { $_.lastbootuptime }
            [datetime]$dtLastReboot = Get-Date -Date ([Management.ManagementDateTimeconverter]::ToDateTime($LastReboot)) -Format yyyy-MM-dd -Date HH:mm:ss

            if($script:Debug) 
            { 
                Write-CHLog -Function 'Main.RebootCheck' -Message ('Last Reboot: {0}' -f $dtLastReboot) 
            }

            [string]$ScriptLastRunDate = Get-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastDate'
            [string]$ScriptLastRunTime = Get-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastTime'
            [datetime]$dtScriptLastRun = [datetime]('{0} {1}' -f $ScriptLastRunDate, $ScriptLastRunTime)

            if($script:Debug) 
            { 
                Write-CHLog -Function 'Main.RebootCheck' -Message ('Last Time Script Ran: {0}' -f $dtLastReboot) 
            }

            if($dtLastReboot -gt $dtScriptLastRun)
            {
                if($script:Debug) 
                { 
                    Write-CHLog -Function 'Main.RebootCheck' -Message 'Setting PFE_RebootPending to False' 
                }

                $RebootPending = $False
                Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_RebootPending' -Data $RebootPending -DataType 'string'
            }
            else 
            { 
                $RebootPending = $True 
            }
        }

        ###############################################################################
        #   Gather System Data
        ###############################################################################

        [string]$Domain = Get-CHRegistryValue -RegKey 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters' -RegValue 'Domain'
        if($Domain -ne '')
        {
            [string]$ResourceName = ('{0}.{1}' -f $($env:COMPUTERNAME), $Domain)
        }
        else
        {
            [string]$ResourceName = $env:COMPUTERNAME
        }

        #Get AD Site Name
        [string]$ADSite = Get-CHRegistryValue -RegKey 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters' -RegValue 'DynamicSiteName'

        #Get AD Machine GUID
        [string]$MachineGUID = Get-CHRegistryValue -RegKey 'HKLM:\Software\Microsoft\Cryptography' -RegValue 'MachineGUID'

        #Get processor architecture from registry
        [string]$OSArch = Get-CHRegistryValue -RegKey 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment' -RegValue 'Processor_Architecture'

        #Update script status in registry
        #
        # Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastAction' -Data 'Gather' -DataType 'string'
        #
        Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastDate' -Data (Get-Date -format yyyy-MM-dd) -DataType 'string'
        Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastTime' -Data (Get-Date -format HH:mm:ss) -DataType 'string'

        ###############################################################################
        #   Check Provisioning Mode
        ###############################################################################

        if($script:SCCMInstalled -eq $True)
        {
            [string]$ProvisioningMode = Get-CHRegistryValue -RegKey HKLM:\SOFTWARE\Microsoft\CCM\CcmExec -RegValue 'ProvisioningMode'
            
            Write-CHLog -Function 'Main.Provisioning' -Message 'Check if client is in provisioning mode'

            if ($ProvisioningMode -ne 'Error')
            {
                if ($ProvisioningMode -eq 'true' -or $ProvisioningMode -eq '')
                {
                    Write-CHLog -Function 'Main.Provisioning' -Message 'Client is in provisioning mode'

                    if(($script:ClientSettings.WorkstationRemediation -eq $true -and $script:OSType -eq 'workstation') -or ($script:ClientSettings.ServerRemediation -eq $true -and $script:OSType -eq 'server'))
                    {
                       Write-CHEventLog -Function 'Main.Provisioning' -Message 'Remediation is enabled, attemptiong to resolve client in Provisioning Mode' -IDType Remediation -Enabled $script:ClientSettings.EventLog

                       Try
                       {
                            Write-CHLog -Function 'Main.Provisioning' -Message 'Setting provisioning mode to false'

                            $null = Invoke-WmiMethod -Namespace 'root\ccm' -Class 'SMS_Client' -Name 'SetClientProvisioningMode' -ArgumentList $false -ErrorAction Stop

                            Write-CHLog -Function 'Main.Provisioning' -Message 'Client no longer in provisioning mode'

                            $ProvisioningMode = 'false'

                            Write-CHEventLog -Function 'Main.Provisioning' -Message 'Remediation is enabled, resolved client in Provisioning Mode' -IDType Remediation -Enabled $script:ClientSettings.EventLog
						                
                            # Moved inside the remediation action
                            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastAction' -Data 'Check Provisioning Mode' -DataType 'string'
                            
                        }
                        Catch
                        {
                            Write-CHLog -Function 'Main.Provisioning' -Message 'Error invoking SetClientProvisioningMode WMI method'
                            Write-CHEventLog -Function 'Main.Provisioning' -Message 'Error invoking SetClientProvisioningMode WMI method' -IDType Error -Enabled $script:ClientSettings.EventLog
                        }
                    }
                    else
                    {
                        Write-CHLog -Function 'Main.Provisioning' -Message 'Remediation has been disabled for this hardware type. Will not repair provisioning mode.'
                    }
                }
                else
                {
                    if($script:Debug) 
                    { 
                        Write-CHLog -Function 'Main.Provisioning' -Message 'Client is not in provisioning mode' 
                    }
                }
            }
            else
            {
                Write-CHLog -Function 'Main.Provisioning' -Message "Couldn't read ProvisioningMode value from the registry."
            }


            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_ProvisioningMode' -Data $ProvisioningMode.ToUpper() -DataType 'string'
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastDate' -Data (Get-Date -format yyyy-MM-dd) -DataType 'string'
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastTime' -Data (Get-Date -format HH:mm:ss) -DataType 'string'

        }
        
        ###############################################################################
        #   Check to see if client is an SCCM site server
        ###############################################################################

        if($script:OSType -eq 'server')
        {
            if((Get-CHRegistryValue -RegKey 'HKLM:\Software\Microsoft\SMS\Components\SMS_EXECUTIVE\Threads\SMS_COMPONENT_MONITOR' -RegValue 'DLL') -eq 'Error')
            {
                if((Get-CHRegistryValue -RegKey 'HKLM:\Software\Microsoft\SMS\Operations Management\SMS Server Role\SMS Distribution Point' -RegValue 'Version') -eq 'Error')
                {
                    [bool]$SiteServer = $False
                    if($script:Debug) 
                    { 
                        Write-CHLog -Function 'Main.IsSiteServer' -Message 'Server is not an SCCM Site Server' 
                    }
                }
                else
                {
                    [bool]$SiteServer = $True
                    Write-CHLog -Function 'Main.IsSiteServer' -Message 'Server is an SCCM Site Server'
                }
            }
            else
            {
                [bool]$SiteServer = $True

                Write-CHLog -Function 'Main.IsSiteServer' -Message 'Server is an SCCM Site Server; checking to see if the server is a Management Point'
                if((Get-CHRegistryValue -RegKey 'HKLM:\Software\Microsoft\SMS\MP' -RegValue 'MP Hostname') -eq '')
                {
                    [bool]$MP = $False
                    if($script:Debug) 
                    { 
                        Write-CHLog -Function 'Main.IsSiteServer' -Message 'Server is not a Management Point' 
                    }
                }
                else
                {
                    [bool]$MP = $True
                    Write-CHLog -Function 'Main.IsSiteServer' -Message 'Server is a Management Point'
                }
            }
        }
        
        Write-CHLog -Function 'Main.Gather' -Message ('CCM Assigned Site: {0}' -f $global:Sitecode)
        Write-CHLog -Function 'Main.Gather' -Message ('Computer Name: {0}' -f $env:COMPUTERNAME)
        Write-CHLog -Function 'Main.Gather' -Message ('Domain Name: {0}' -f $Domain)
        Write-CHLog -Function 'Main.Gather' -Message ('FQDN: {0}' -f $ResourceName)
        Write-CHLog -Function 'Main.Gather' -Message ('System Type: {0}' -f $script:OSType)
        Write-CHLog -Function 'Main.Gather' -Message ('Architecture Type: {0}' -f $OSArch)
        Write-CHLog -Function 'Main.Gather' -Message ('Operating System: {0}' -f $OSName)


        ###############################################################################
        #   Check Free MB on System Drive
        ###############################################################################
        
        [int]$SystemDriveMBFree = [int]((Get-PSDrive -Name $($env:SystemDrive)[0]).Free / 1MB)

        if($script:Debug){ Write-CHLog -Function 'Main.Gather' -Message ('Free space on {0} is {1} MB' -f $env:SystemDrive, $SystemDriveMBFree) }

        if($SystemDriveMBFree -lt 512)
        {
            Write-CHLog -Function 'Main.DriveMBFree' -Message "Error - System drive $env:SystemDrive has less than 500MB free space. Script will not attempt to install client"
            Write-CHEventLog -Function 'Main.DriveMBFree' -Message "Error - System drive $env:SystemDrive has less than 500MB free space. Script will not attempt to install client" -IDType Error -Enabled $script:ClientSettings.EventLog
        }

        Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_CFreeSpace' -Data $SystemDriveMBFree -DataType 'string'

        ###############################################################################
        #   Start Services Check
        ###############################################################################

        Write-CHLog -Function 'Main.ServicesCheck' -Message 'Beginning Service Verification'

        ###############################################################################
        #   Check BITS Service
        ###############################################################################

        if($script:ClientSettings.BITSService -eq $True)
        {
            [string]$BITSHealth = 'Unhealthy'

            if($script:Debug)
            { 
                Write-CHLog -Function 'Main.BITSService' -Message 'Beginning BITS Service Verification' 
            }

            if(!(Get-CHServiceStatus -ServiceName 'BITS' -StartType NotDisabled -Status NotMonitored))
            {
                if($script:ClientSettings.ServerRemediation -eq $true -and $script:OSType -eq 'server')
                {
                    if((Set-CHServiceStatus -ServiceName 'BITS' -StartType Manual -Status Running) -eq $true)
                    {
                        [string]$BITSHealth = 'Healthy'
                        Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastAction' -Data 'BITS Service' -DataType 'string'
                    }
                    else
                    { 
                        [string]$BITSHealth = 'Unhealthy' 
                    }
                }
                elseif($script:ClientSettings.WorkstationRemediation -eq $true -and $script:OSType -eq 'workstation')
                {
                    if((Set-CHServiceStatus -ServiceName 'BITS' -StartType DelayedAuto -Status Running) -eq $true)
                    {
                        [string]$BITSHealth = 'Healthy'
                        Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastAction' -Data 'BITS Service' -DataType 'string'
                    }
                    else
                    { 
                        [string]$BITSHealth = 'Unhealthy' 
                    }
                }
                else
                { 
                    if($script:Debug) 
                    {
                        Write-CHLog -Function 'Main.BITSService' -Message 'Remediation disabled; will not attempt to remediate BITS' 
                    }
                    [string]$BITSHealth = 'Unhealthy'
                }
            }
            else{ [string]$BITSHealth = 'Healthy' }

            #Update script status in registry
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_BITSStatus' -Data $BITSHealth -DataType 'string'
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastDate' -Data (Get-Date -format yyyy-MM-dd) -DataType 'string'
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastTime' -Data (Get-Date -format HH:mm:ss) -DataType 'string'
        }


        ###############################################################################
        #   Check BITS Queue
        ###############################################################################

        if($script:ClientSettings.BITSQueue -eq $True)
        {
            [string]$BITSQueue = 'Unhealthy'

            Write-CHLog -Function 'Main.BITSQueue' -Message 'Beginning BITS Queue Verification'
            Write-CHEventLog -Function 'Main.BITSQueue' -Message 'Beginning BITS Queue Verification' -IDType Remediation -Enabled $script:ClientSettings.EventLog

            [bool]$BITSQueueState = $false
            $BITSQueueState = Clear-BITSQueue
            
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastAction' -Data 'BITS Queue' -DataType 'string'
            Write-CHLog -Function 'Main.BITSQueue' -Message 'Completed BITS Queue Verification'
            Write-CHEventLog -Function 'Main.BITSQueue' -Message 'Completed BITS Queue Verification' -IDType Remediation -Enabled $script:ClientSettings.EventLog

            if ($BITSQueueState) {$BITSQueue = 'Healthy'}
        }
        else
        {
            [string]$BITSQueue = 'Unhealthy'

            Write-CHLog -Function 'Main.BITSQueue' -Message 'Beginning BITS Queue Verification'

            [bool]$BITSQueueState = Clear-BITSQueue -logonly

            Write-CHLog -Function 'Main.BITSQueue' -Message 'Completed BITS Queue Verification'

            if ($BITSQueueState) {$BITSQueue = 'Healthy'}
        }

            #Update script status in registry
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_BITSQueue' -Data $BITSQueue -DataType 'string'
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastDate' -Data (Get-Date -format yyyy-MM-dd) -DataType 'string'
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastTime' -Data (Get-Date -format HH:mm:ss) -DataType 'string'

        ###############################################################################
        #   Check Windows Update Service
        ###############################################################################

        if($script:ClientSettings.WUAService -eq $True)
        {
            [string]$WUAHealth = 'Unhealthy'

            if($script:Debug)
            { 
                Write-CHLog -Function 'Main.WUAService' -Message 'Beginning Windows Update Agent Service Verification' 
            }

            if($script:OSVersion -ne '6.1')
            {
                if(!(Get-CHServiceStatus -ServiceName 'wuauserv' -StartType Manual -Status NotMonitored))
                {
                    if(($script:ClientSettings.WorkstationRemediation -eq $true -and $script:OSType -eq 'workstation') -or ($script:ClientSettings.ServerRemediation -eq $true -and $script:OSType -eq 'server'))
                    {
                        if((Set-CHServiceStatus -ServiceName 'wuauserv' -StartType Manual -Status Running) -eq $true)
                        {
                            [string]$WUAHealth = 'Healthy'
                            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastAction' -Data 'WUA Service' -DataType 'string'
                        }
                    }
                    else
                    { 
                        if($script:Debug)
                        { 
                            Write-CHLog -Function 'Main.WUAService' -Message 'Remediation disabled; will not attempt to remediate Windows Update Agent Service'
                        } 
                    }
                }
                else
                { 
                    [string]$WUAHealth = 'Healthy' 
                }
            }
            else
            {
                if(!(Get-CHServiceStatus -ServiceName 'wuauserv' -StartType DelayedAuto -Status Running))
                {
                    if(($script:ClientSettings.WorkstationRemediation -eq $true -and $script:OSType -eq 'workstation') -or ($script:ClientSettings.ServerRemediation -eq $true -and $script:OSType -eq 'server'))
                    {
                        if((Set-CHServiceStatus -ServiceName 'wuauserv' -StartType DelayedAuto -Status Running) -eq $true)
                        {
                            [string]$WUAHealth = 'Healthy'
                            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastAction' -Data 'WUA Service' -DataType 'string'
                        }
                    }
                    else
                    { 
                        if($script:Debug)
                        { 
                            Write-CHLog -Function 'Main.WUAService' -Message 'Remediation disabled; will not attempt to remediate Windows Update Agent Service'
                        } 
                    }
                }
                else
                { 
                    [string]$WUAHealth = 'Healthy' 
                }
            }

            #Update script status in registry
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_WUAStatus' -Data $WUAHealth -DataType 'string'
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastDate' -Data (Get-Date -format yyyy-MM-dd) -DataType 'string'
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastTime' -Data (Get-Date -format HH:mm:ss) -DataType 'string'
        }

        ###############################################################################
        #   Check Windows Management Instrumentation (WMI) Service
        ###############################################################################

        if($script:ClientSettings.WMIService -eq $True)
        {
            [string]$WMIService = 'Unhealthy'

            if($script:Debug)
            { 
                Write-CHLog -Function 'Main.WMIService' -Message 'Beginning WMI Service Verification' 
            }

            if(!(Get-CHServiceStatus -ServiceName 'winmgmt' -StartType Automatic -Status Running))
            {
                if(($script:ClientSettings.WorkstationRemediation -eq $true -and $script:OSType -eq 'workstation') -or ($script:ClientSettings.ServerRemediation -eq $true -and $script:OSType -eq 'server'))
                {
                    if((Set-CHServiceStatus -ServiceName 'winmgmt' -StartType Automatic -Status Running) -eq $True)
                    {
                        [string]$WMIService = 'Healthy'
                        Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastAction' -Data 'WMI Service' -DataType 'string'
                    }
                }
                else
                { 
                    if($script:Debug)
                    { 
                        Write-CHLog -Function 'Main.WMIService' -Message 'Remediation disabled; will not attempt to remediate WMI Service' 
                    } 
                }
            }
            else
            { 
                [string]$WMIService = 'Healthy' 
            }

            #Update script status in registry
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_WMIStatus' -Data $WMIService -DataType 'string'
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastDate' -Data (Get-Date -format yyyy-MM-dd) -DataType 'string'
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastTime' -Data (Get-Date -format HH:mm:ss) -DataType 'string'
        }

        ###############################################################################
        #   Check CCMExec Service
        ###############################################################################

        if($script:ClientSettings.CCMService -eq $True)
        {
            [string]$CCMHealth = 'Unhealthy'

            if($script:Debug)
            { 
                Write-CHLog -Function 'Main.CCMEXECService' -Message 'Beginning SMS Agent Host Service Verification' 
            }

            if($MP)
            {
                if(!(Get-CHServiceStatus -ServiceName 'ccmexec' -StartType Automatic -Status Running))
                {
                    if((get-service -Name ccmexec -ErrorAction SilentlyContinue) -eq $null)
                    {
                        Write-CHLog -Function 'Main.CCMEXECService' -Message 'Warning - SMS Agent Host Service is not installed'
                        Write-CHEventLog -Function 'Main.CCMEXECService' -Message 'Warning - SMS Agent Host Service is not installed' -IDType Error -Enabled $script:ClientSettings.EventLog
                        [bool]$script:SCCMInstalled = $False
                    }
                    else
                    {
                        if(($script:ClientSettings.WorkstationRemediation -eq $true -and $script:OSType -eq 'workstation') -or ($script:ClientSettings.ServerRemediation -eq $true -and $script:OSType -eq 'server'))
                        {
                            if((Set-CHServiceStatus -ServiceName 'ccmexec' -StartType Automatic -Status Running) -eq $True)
                            {
                                [string]$CCMHealth = 'Healthy'
                                Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastAction' -Data 'SMS Agent Host Service' -DataType 'string'
                            }
                        }
                        else
                        { 
                            if($script:Debug)
                            { 
                                Write-CHLog -Function 'Main.CCMEXECService' -Message 'Remediation disabled; will not attempt to remediate SMS Agent Host Service' 
                            } 
                        }
                    }
                }
                else
                {
                    [string]$CCMHealth = 'Healthy'
                    if($script:SCCMInstalled -eq $False)
                    {
                        Write-CHLog -Function 'Main.CCMEXECService' -Message 'Error - Server is an MP and the SMS Agent Host Service is present, but the client is not found; will install client if remediation is enabled'
                        Write-CHEventLog -Function 'Main.CCMEXECService' -Message 'Error - Server is an MP and the SMS Agent Host Service is present, but the client is not found; will install client if remediation is enabled' -IDType Error -Enabled $script:ClientSettings.EventLog
                        [string]$CCMHealth = 'Unhealthy'
                    }
                }
            }
            else
            {
                if(!(Get-CHServiceStatus -ServiceName 'ccmexec' -StartType DelayedAuto -Status Running))
                {
                    if((Get-Service -Name ccmexec -ErrorAction SilentlyContinue) -eq $null)
                    {
                        Write-CHLog -Function 'Main.CCMEXECService' -Message 'Warning - SMS Agent Host Service is not installed'
                        Write-CHEventLog -Function 'Main.CCMEXECService' -Message 'Warning - SMS Agent Host Service is not installed' -IDType Error -Enabled $script:ClientSettings.EventLog
                        [string]$CCMHealth = 'Unhealthy'
                        [bool]$script:SCCMInstalled = $False
                    }                    
                    else
                    {
                        if(($script:ClientSettings.WorkstationRemediation -eq $true -and $script:OSType -eq 'workstation') -or ($script:ClientSettings.ServerRemediation -eq $true -and $script:OSType -eq 'server'))
                        {
                            if((Set-CHServiceStatus -ServiceName 'ccmexec' -StartType DelayedAuto -Status Running) -eq $True)
                            {
                                [string]$CCMHealth = 'Healthy'
                                Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastAction' -Data 'SMS Agent Host Service' -DataType 'string'
                            }
                        }
                        else
                        { 
                            if($script:Debug)
                            { 
                                Write-CHLog -Function 'Main.CCMEXECService' -Message 'Remediation disabled; will not attempt to remediate SMS Agent Host Service' 
                            } 
                        }
                    }
                }
                else
                { 
                    [string]$CCMHealth = 'Healthy' 
                }
            }

            #Update script status in registry
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_CCMStatus' -Data $CCMHealth -DataType 'string'
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastDate' -Data (Get-Date -format yyyy-MM-dd) -DataType 'string'
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastTime' -Data (Get-Date -format HH:mm:ss) -DataType 'string'
        }

        ###############################################################################
        #   Check Policy Platform Local Authority Service
        ############################################################################### 

        if($script:ClientSettings.PolicyPlatformLocalAuthorityService -eq $True -and $script:SCCMInstalled)
        {
            [string]$PPLAHealth = 'Unhealthy'

            if($script:Debug)
            { 
                Write-CHLog -Function 'Main.PLAServices' -Message 'Beginning Policy Platform Local Authority Service Verification' 

            }

            if(!(Get-CHServiceStatus -ServiceName 'lpasvc' -StartType Manual -Status NotMonitored))
            {
                if(($script:ClientSettings.WorkstationRemediation -eq $true -and $script:OSType -eq 'workstation') -or ($script:ClientSettings.ServerRemediation -eq $true -and $script:OSType -eq 'server'))
                {
                    if((Set-CHServiceStatus -ServiceName 'lpasvc' -StartType Manual -Status Running) -eq $True)
                    {
                        [string]$PPLAHealth = 'Healthy'
                        Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastAction' -Data 'Policy Platform Local Authority Service' -DataType 'string'
                    }
                }
                else
                { 
                    if($script:Debug)
                    { 
                        Write-CHLog -Function 'Main.PLAServices' -Message 'Remediation disabled; will not attempt to remediate Policy Platform Local Authority Service' 
                    } 
                }
            }
            else
            { 
                [string]$PPLAHealth = 'Healthy' 
            }

            #Update script status in registry
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_PolicyPlatformLAStatus' -Data $PPLAHealth -DataType 'string'
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastDate' -Data (Get-Date -format yyyy-MM-dd) -DataType 'string'
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastTime' -Data (Get-Date -format HH:mm:ss) -DataType 'string'
        }

        ###############################################################################
        #   Check Policy Platform Processor Service
        ###############################################################################

        if($script:ClientSettings.PolicyPlatformProcessorService -eq $True -and $script:SCCMInstalled)
        {
            [string]$PPPHealth = 'Unhealthy'

            if($script:Debug)
            { 
                Write-CHLog -Function 'Main.PPPService' -Message 'Beginning Policy Platform Processor Service Verification' 
            }

            if(!(Get-CHServiceStatus -ServiceName 'lppsvc' -StartType Manual -Status NotMonitored))
            {
                if(($script:ClientSettings.WorkstationRemediation -eq $true -and $script:OSType -eq 'workstation') -or ($script:ClientSettings.ServerRemediation -eq $true -and $script:OSType -eq 'server'))
                {
                    if((Set-CHServiceStatus -ServiceName 'lppsvc' -StartType Manual -Status Running) -eq $True)
                    {
                        [string]$PPPHealth = 'Healthy'
                        Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastAction' -Data 'Policy Platform Processor Service' -DataType 'string'
                    }
                }
                else
                { 
                    if($script:Debug)
                    { 
                        Write-CHLog -Function 'Main.PPPService' -Message 'Remediation disabled; will not attempt to remediate Policy Platform Processor Service' 
                    } 
                }
            }
            else
            { 
                [string]$PPPHealth = 'Healthy' 
            }

            #Update script status in registry
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_PolicyPlatformProcessorStatus' -Data $PPPHealth -DataType 'string'
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastDate' -Data (Get-Date -format yyyy-MM-dd) -DataType 'string'
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastTime' -Data (Get-Date -format HH:mm:ss) -DataType 'string'
        }

        ###############################################################################
        #   Check Alternate Content Provider Service
        ###############################################################################

        if($script:ClientSettings.ACPService -eq $True)
        {
            [string]$ACPHealth = 'Unhealthy'

            if($script:Debug){ Write-CHLog -Function 'Main.ServicesCheck' -Message ('Beginning {0} Service Verification' -f $($script:ClientSettings.ACPServiceName)) }

            if((Get-CHServiceStatus -ServiceName $($script:ClientSettings.ACPServiceName) -StartType $script:ClientSettings.ACPServiceStartType -Status Running) -eq $True)
            {
                if($script:Debug){ Write-CHLog -Function 'Main.ServicesCheck' -Message ('{0} is Healthy' -f $script:ClientSettings.ACPServiceName) }
                [string]$ACPHealth = 'Healthy'
            }
            else
            {
                if(($script:ClientSettings.WorkstationRemediation -eq $true -and $script:OSType -eq 'workstation') -or ($script:ClientSettings.ServerRemediation -eq $true -and $script:OSType -eq 'server'))
                {
                    if((Get-Service -Name $($script:ClientSettings.ACPServiceName) -ErrorAction SilentlyContinue) -eq $null)
                    {
                        [bool]$ACPInstall = $True
                        Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastAction' -Data 'ACP Service' -DataType 'string'
                    }
                    else
                    {
                        if((Set-CHServiceStatus -ServiceName $($script:ClientSettings.ACPServiceName) -StartType $script:ClientSettings.ACPServiceStartType -Status Running) -eq $True)
                        {
                            if($script:Debug){ Write-CHLog -Function 'Main.ServicesCheck' -Message ('{0} is Healthy' -f $($script:ClientSettings.ACPServiceName)) }
                            [string]$ACPHealth = 'Healthy'
                        }
                        else{  Write-CHLog -Function 'Main.ServicesCheck' -Message ('Error - Remediation of {0} failed' -f $($script:ClientSettings.ACPServiceName)) }
                    }
                }
                else
                { 
                    if($script:Debug)
                    { 
                        Write-CHLog -Function 'Main.ServicesCheck' -Message ('Remediation disabled; will not attempt to remediate {0} Service' -f $script:ClientSettings.ACPServiceName) 
                    } 
                }
            }

            #Update script status in registry
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_ACPStatus' -Data $ACPHealth -DataType 'string'
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastDate' -Data (Get-Date -format yyyy-MM-dd) -DataType 'string'
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastTime' -Data (Get-Date -format HH:mm:ss) -DataType 'string'
        }

        ###############################################################################
        #   Check WMI Health
        ###############################################################################

        if($script:ClientSettings.WMIReadRepository -eq $True -and $WMIService -eq 'Healthy')
        {
            [string]$WMIReadRepository = 'Healthy'
            [string]$WMIWriteRepository = 'Healthy'

            Write-CHLog -Function 'Main.WMIHealth' -Message 'Beginning WMI repository verification'

            if(!(Test-CHWMIHealth))
            {
                Write-CHLog -Function 'Main.WMIHealth' -Message 'Error - WMI repository verification failed'
                Write-CHEventLog -Function 'Main.WMIHealth' -Message 'Error - WMI repository verification failed' -IDType Error -Enabled $script:ClientSettings.EventLog
                [string]$WMIReadRepository = 'Unhealthy'
                [string]$WMIWriteRepository = 'Unhealthy'
                [bool]$WMIHealth = $False
            }
            else
            {
                Write-CHLog -Function 'Main.WMIHealth' -Message 'WMI repository verification was successful'
                Write-CHEventLog -Function 'Main.WMIHealth' -Message 'WMI repository verification was successful' -IDType Remediation -Enabled $script:ClientSettings.EventLog
                [bool]$WMIHealth = $True
            }

            #Update script status in registry
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_WMIReadRepository' -Data $WMIReadRepository -DataType 'string'
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_WMIWriteRepository' -Data $WMIWriteRepository -DataType 'string'
            #
            # Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastAction' -Data 'WMI Verification' -DataType 'string'
            #           
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastDate' -Data (Get-Date -format yyyy-MM-dd) -DataType 'string'
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastTime' -Data (Get-Date -format HH:mm:ss) -DataType 'string'
        }
        else
        {
            if($WMIService -ne 'Healthy')
            {
                Write-CHLog -Function 'Main.WMIHealth' -Message 'Warning - Will not attempt WMI read repository as WMI Service health is unhealthy'
                Write-CHEventLog -Function 'Main.WMIHealth' -Message 'Warning - Will not attempt WMI read repository as WMI Service health is unhealthy' -IDType Error -Enabled $script:ClientSettings.EventLog
                Write-CHLog -Function 'Main.WMIHealth' -Message 'Warning - Verify Windows Management Instrumentation Service is set to Automatic and is Running'
                Write-CHEventLog -Function 'Main.WMIHealth' -Message 'Warning - Verify Windows Management Instrumentation Service is set to Automatic and is Running' -IDType Error -Enabled $script:ClientSettings.EventLog
            }
            else
            {
                Write-CHLog -Function 'Main.WMIHealth' -Message 'Warning - Client Setting WMIReadRepository from XML file is not set to True; no verification performed'
            }
        }

        ###############################################################################
        #   Rebuild WMI
        ###############################################################################

        if($script:ClientSettings.WMIRebuild -eq $True -and ($WMIReadRepository -eq 'Unhealthy' -or $WMIWriteRepository -eq 'Unhealthy') -and $script:OSType -eq 'workstation' -and $WMIService -eq 'Healthy' -and $script:ClientSettings.WorkstationRemediation -eq $True)
        {
            Write-CHLog -Function 'Main.RebuildWMI' -Message 'Beginning WMI rebuild'

            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastAction' -Data 'WMI Rebuild' -DataType 'string'
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastDate' -Data (Get-Date -format yyyy-MM-dd) -DataType 'string'
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastTime' -Data (Get-Date -format HH:mm:ss) -DataType 'string'

            if(Invoke-CHWMIRebuild -eq $True)
            {
                Write-CHLog -Function 'Main.RebuildWMI' -Message 'WMI Rebuild Successful'
                Write-CHEventLog -Function 'Main.RebuildWMI' -Message 'WMI Rebuild Successful' -IDType Remediation -Enabled $script:ClientSettings.EventLog
            }
            else
            {
                Write-CHLog -Function 'Main.RebuildWMI' -Message 'Error - WMI rebuild failed; will not attempt to reinstall SCCM client'
                Write-CHEventLog -Function 'Main.RebuildWMI' -Message 'Error - WMI rebuild failed; will not attempt to reinstall SCCM client' -IDType Error -Enabled $script:ClientSettings.EventLog
            }
        }
        elseif($script:ClientSettings.WMIRebuild -eq $False -and ($WMIReadRepository -eq 'Unhealthy' -or $WMIWriteRepository -eq 'Unhealthy') -and $WMIService -eq 'Healthy')
        {
            Write-CHLog -Function 'Main.RebuildWMI' -Message 'Warning - WMI is unhealthy, however the client Setting WMIRebuild from XML file is not set to True; WMI will not be rebuilt'
            Write-CHEventLog -Function 'Main.RebuildWMI' -Message 'Warning - WMI is unhealthy, however the client Setting WMIRebuild from XML file is not set to True; WMI will not be rebuilt' -IDType NoRemediation -Enabled $script:ClientSettings.EventLog
        }
        elseif($script:ClientSettings.WMIRebuild -eq $True -and ($WMIReadRepository -eq 'Unhealthy' -or $WMIWriteRepository -eq 'Unhealthy') -and $script:OSType -eq 'workstation' -and $script:ClientSettings.WorkstationRemediation -eq $False)
        {
            Write-CHLog -Function 'Main.RebuildWMI' -Message 'Warning - WMI is unhealthy, however the client Setting WorkstationRemediation from XML file is not set to True; WMI will not be rebuilt'
            Write-CHEventLog -Function 'Main.RebuildWMI' -Message 'Warning - WMI is unhealthy, however the client Setting WorkstationRemediation from XML file is not set to True; WMI will not be rebuilt' -IDType NoRemediation -Enabled $script:ClientSettings.EventLog
        }
        elseif($script:OSType -eq 'server' -and ($WMIReadRepository -eq 'Unhealthy' -or $WMIWriteRepository -eq 'Unhealthy'))
        {
            Write-CHLog -Function 'Main.RebuildWMI' -Message 'Warning - WMI is unhealthy but the client has a Server Operating System; WMI will not be rebuilt'
            Write-CHEventLog -Function 'Main.RebuildWMI' -Message 'Warning - WMI is unhealthy but the client has a Server Operating System; WMI will not be rebuilt' -IDType NoRemediation -Enabled $script:ClientSettings.EventLog
        }
        elseif($WMIService -ne 'Healthy')
        {
            Write-CHLog -Function 'Main.RebuildWMI' -Message 'Warning - Will not attempt to rebuild WMI repository as WMI Service health is unknown or unhealthy'
            Write-CHLog -Function 'Main.RebuildWMI' -Message 'Warning - Check if client setting WMIService is not set to True; if not True, the service was not checked and overall WMI health was not verified'
            Write-CHLog -Function 'Main.RebuildWMI' -Message 'Warning - Verify Windows Management Instrumentation Service is set to Automatic and is Running.'
            Write-CHEventLog -Function 'Main.RebuildWMI' -Message 'Warning - Will not attempt to rebuild WMI repository as WMI Service health is unknown or unhealthy' -IDType Error -Enabled $script:ClientSettings.EventLog
            Write-CHEventLog -Function 'Main.RebuildWMI' -Message 'Warning - Check if client setting WMIService is not set to True; if not True, the service was not checked and overall WMI health was not verified' -IDType Error -Enabled $script:ClientSettings.EventLog
            Write-CHEventLog -Function 'Main.RebuildWMI' -Message 'Warning - Verify Windows Management Instrumentation Service is set to Automatic and is Running.' -IDType Error -Enabled $script:ClientSettings.EventLog
        }

        <###############################################################################
          * DCOM Verification and Remediation
          * Checks HKLM:\Software\Microsoft\Ole\EnableDCOM to see if value is Y
          * If not and remediation is enabled, value is set to Y.  Reboot is required for DCOM to be enabled.
          * Script wil not reboot
          * Also checks DCOM Protocols to see if Connection Oriented TCP/IP connection is enabled
        ###############################################################################>

        if($script:ClientSettings.WMIReadRepository -and $script:ClientSettings.DCOMVerify)
        {
            Write-CHLog -Function 'Main.DCOMHealth' -Message 'Checking DCOM health'

            [string]$DCOMHealth = 'Healthy'
            [string]$DCOMProtocolHealth = 'Healthy'

            [string]$DCOM = Get-CHRegistryValue -RegKey 'HKLM:\Software\Microsoft\Ole' -RegValue 'EnableDCOM'
            [array]$DCOMProtocols = Get-CHRegistryValue -RegKey 'HKLM:\Software\Microsoft\RPC' -RegValue 'DCOM Protocols'

            if($DCOMProtocols[0] -eq '')
            {
                [string]$DCOMProtocolHealth = 'Unhealthy'

                Write-CHLog -Function 'Main.DCOMHealth' -Message 'Error - DCOM protocols are missing; if remediation is enabled, this will be created'
                Write-CHEventLog -Function 'Main.DCOMHealth' -Message 'Error - DCOM protocols are missing; if remediation is enabled, this will be created' -IDType Error -Enabled $script:ClientSettings.EventLog

                if(($script:OSType -eq 'workstation' -and $script:ClientSettings.WorkstationRemediation -eq $True) -or ($script:OSType -eq 'server' -and $script:ClientSettings.ServerRemediation -eq $True))
                {
                    [string]$DCOMProtocol = 'ncacn_ip_tcp'
                    if((Set-CHRegistryValue -RegKey 'HKLM:\Software\Microsoft\RPC' -RegValue 'DCOM Protocols' -Data $DCOMProtocol -DataType multistring) -eq $True)
                    {
                        [string]$DCOMProtocolHealth = 'Healthy'
                        [string]$PFEReboot = 'True'
                        Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastAction' -Data 'DCOM' -DataType 'string'
                    }
                    else
                    {
                        [string]$DCOMProtocolHealth = 'Unhealthy'
                    }
                }
                else
                { 
                    Write-CHLog -Function 'Main.DCOMHealth' -Message 'Error - DCOM protocols are missing, but remediation is disabled for this hardware type; will not modify DCOM protocols' 
                }
            }
            elseif($DCOMProtocols -Contains 'ncacn_ip_tcp')
            {
                if($script:Debug)
                { 
                    Write-CHLog -Function 'Main' -Message 'DCOM Protocols are configured correctly' 
                }
            }
            else
            {
                Write-CHLog -Function 'Main.DCOMHealth' -Message 'Error - DCOM Protocols are not configured correctly'
                Write-CHEventLog -Function 'Main.DCOMHealth' -Message 'Error - DCOM Protocols are not configured correctly' -IDType Error -Enabled $script:ClientSettings.EventLog

                if(($script:OSType -eq 'workstation' -and $script:ClientSettings.WorkstationRemediation -eq $True) -or ($script:OSType -eq 'server' -and $script:ClientSettings.ServerRemediation -eq $True))
                {
                    Write-CHLog -Function 'Main.DCOMHealth' -Message 'DCOM Protocol ncacn_ip_tcp is missing; adding it to the existing list of protocols'
                    Write-CHEventLog -Function 'Main.DCOMHealth' -Message 'DCOM Protocol ncacn_ip_tcp is missing; adding it to the existing list of protocols' -IDType Remediation -Enabled $script:ClientSettings.EventLog
                    Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastAction' -Data 'DCOM' -DataType 'string'

                    [string]$DCOMProtocols = ''
                    foreach($DCOMProtocol in $DCOMProtocols)
                    {
                        if($DCOMProtocols -eq '')
                        {
                            $DCOMProtocols = $DCOMProtocol
                        }
                        else
                        {
                            $DCOMProtocols = ('{0},{1}' -f $DCOMProtocols, $DCOMProtocol)
                        }
                    }
                    $DCOMProtocols = ('{0},ncacn_ip_tcp' -f $DCOMProtocols)
                    if((Set-CHRegistryValue -RegKey 'HKLM:\Software\Microsoft\RPC' -RegValue 'DCOM Protocols' -Data $DCOMProtocols -DataType multistring) -eq $True)
                    {
                        [string]$DCOMProtocolHealth = 'Healthy'
                        [string]$PFEReboot = 'True'
                    }
                    else
                    {
                        [string]$DCOMProtocolHealth = 'Unhealthy'
                    }
                }
                else
                { 
                    Write-CHLog -Function 'Main.DCOMHealth' -Message 'Error - DCOM protocols are missing, but remediation is disabled for this hardware type; will not modify DCOM protocols' 
                }
            }

            if($DCOM -ne 'Y')
            {
                [string]$DCOMHealth = 'Unhealthy'
                Write-CHLog -Function 'Main.DCOMHealth' -Message 'Error - DCOM is not enabled; if remediation is enabled, it will be enabled'
                Write-CHEventLog -Function 'Main.DCOMHealth' -Message 'Error - DCOM is not enabled; if remediation is enabled, it will be enabled' -IDType Error -Enabled $script:ClientSettings.EventLog

                if(($script:OSType -eq 'workstation' -and $script:ClientSettings.WorkstationRemediation -eq $True) -or ($script:OSType -eq 'server' -and $script:ClientSettings.ServerRemediation -eq $True))
                {
                    [string]$DCOMProtocols = 'ncacn_ip_tcp'
                    if((Set-CHRegistryValue -RegKey 'HKLM:\Software\Microsoft\Ole' -RegValue 'EnableDCOM' -Data 'Y' -DataType string) -eq $True)
                    {
                        [string]$DCOMHealth = 'Healthy'
                        [string]$PFEReboot = 'True'
                        Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastAction' -Data 'DCOM' -DataType 'string'
                    }
                    else
                    {
                        [string]$DCOMHealth = 'Unhealthy'
                    }
                }
                else
                { 
                    Write-CHLog -Function 'Main.DCOMHealth' -Message 'Error - DCOM is not enabled, but remediation is disabled for this hardware type; will not enable DCOM' 
                }
            }
            else 
            { 
                if($script:Debug)
                { 
                    Write-CHLog -Function 'Main.DCOMHealth' -Message 'DCOM is enabled' 
                } 
            }

            #Update script status in registry
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_DCOM' -Data $DCOMHealth -DataType 'string'
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_DCOMProtocols' -Data $DCOMProtocolHealth -DataType 'string'
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_PFERebootPending' -Data $PFEReboot -DataType 'string'
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastDate' -Data (Get-Date -format yyyy-MM-dd) -DataType 'string'
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastTime' -Data (Get-Date -format HH:mm:ss) -DataType 'string'
        }

        ###############################################################################
        #   Check Stale Logs
        ###############################################################################

        if($script:SCCMInstalled -eq $True)
        {
            [array]$LogFiles = @('PolicyEvaluator','InventoryAgent')

            Write-CHLog -Function 'Main.StaleLogs' -Message 'Checking if log files are stale'

            [string]$StaleLogFiles = ''
            [bool]$SCCMClientRepair = $False

            foreach($SCCMLogFile in $LogFiles)
            {
                if((Test-CHStaleLog -LogFileName $SCCMLogFile -DaysStale $script:ClientSettings.LogDaysStale) -eq $True)
                {
                    if($StaleLogFiles -eq '')
                    {
                        $StaleLogFiles = $SCCMLogFile
                    }
                    else
                    {
                        $StaleLogFiles = ('{0},{1}' -f $StaleLogFiles, $SCCMLogFile)
                    }
                    [bool]$SCCMClientRepair = $True
                }
            }

            if($StaleLogFiles -eq ''){ $StaleLogFiles = 'Healthy' }

            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_PFEStaleLogs' -Data $StaleLogFiles -DataType 'string'
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastDate' -Data (Get-Date -format yyyy-MM-dd) -DataType 'string'
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastTime' -Data (Get-Date -format HH:mm:ss) -DataType 'string'
        }

        ###############################################################################
        #   Collect Inventory
        ###############################################################################

        if($script:SCCMInstalled -eq $True)
        {
            Write-CHLog -Function 'Main.CollectInventory' -Message 'Start Collecting Inventory'
            
            #Create empty array to hold inventory types for action
            $InventoryAction = @()
            
            if (($script:ClientSettings.HWINV) -eq $true) { $InventoryAction += ,('PFE_HWINVDate (UTC)','InventoryActionID = "{00000000-0000-0000-0000-000000000001}"','Error collecting hardware data from WMI') }
            if (($script:ClientSettings.SWINV) -eq $true) { $InventoryAction += ,('PFE_SWINVDate (UTC)','InventoryActionID = "{00000000-0000-0000-0000-000000000002}"','Error collecting software data from WMI') }
            if (($script:ClientSettings.Heartbeat) -eq $true) { $InventoryAction += ,('PFE_HeartbeatDate (UTC)','InventoryActionID = "{00000000-0000-0000-0000-000000000003}"','Error collecting heartbeat data from WMI') }
            
            foreach ($Action in $InventoryAction)
            {
                Try
                {
                    $Inv = Get-WmiObject -Class InventoryActionStatus -Namespace 'root\ccm\invagt' -Filter $Action[1] -ErrorAction Stop
                    if ($Inv.GetType())
                    {
                        foreach ($Inv in $Inv)
                        {
                            [datetime]$dtmInvDate = Get-Date -Date ([Management.ManagementDateTimeconverter]::ToDateTime($Inv.LastReportDate)) -Format 'yyyy-MM-dd HH:mm:ss'
                            [string]$dtmInvDateUTC = ('{0:yyyy-MM-dd HH:mm:ss}' -f $dtmInvDate.ToUniversalTime())
                            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue $Action[0] -Data $dtmInvDateUTC -DataType 'string'
                        }
                    }
                }
                Catch
                {
                    Write-CHLog -Function 'Main.CollectInventory' -Message $Action[2]
                    Write-CHEventLog -Function 'Main.CollectInventory' -Message $Action[2] -IDType Error -Enabled $script:ClientSettings.EventLog
                }
            }

            #update status in registry
            #
            #Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastAction' -Data 'Collect Inventory Dates' -DataType 'string'
            #
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastDate' -Data (Get-Date -format yyyy-MM-dd) -DataType 'string'
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastTime' -Data (Get-Date -format HH:mm:ss) -DataType 'string'
        }

        ###############################################################################
        #   Check Lantern Application CI
        ###############################################################################

        if($script:SCCMInstalled -eq $True -and $script:ClientSettings.LanternAppCI -eq $True)
        {
            Write-CHLog -Function 'Main.CheckLantern' -Message 'Checking Application Deployment Policy matches Application CI'

            if(!(Test-CHLantern))
            {
                [string]$LanternAppCI = 'Unhealthy'
                $SCCMClientRepair = $True
                Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastAction' -Data 'Lantern Application Test' -DataType 'string'
            }
            else
            {
                [string]$LanternAppCI = 'Healthy'
            }

            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LanternAppCI' -Data $LanternAppCI -DataType 'string'
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastDate' -Data (Get-Date -format yyyy-MM-dd) -DataType 'string'
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastTime' -Data (Get-Date -format HH:mm:ss) -DataType 'string'
        }

        ###############################################################################
        #   Check BITS Queue
        ###############################################################################
 
        if($script:ClientSettings.BITSQueue -eq $True)
        {
            
            if(($script:OSType -eq 'workstation' -and $script:ClientSettings.WorkstationRemediation -eq $True) -or ($script:OSType -eq 'server' -and $script:ClientSettings.ServerRemediation -eq $True))
            {
                Write-CHLog -Function 'Check BITS Queue' -Message 'Remediation is enabled, checking BITS queue.'
                $null = Clear-BITSQueue
                Write-CHLog -Function 'Check BITS Queue' -Message 'Remediation is enabled, checking BITS queue complete.'
                Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastAction' -Data 'BITS Queue' -DataType 'string'
                
            }
            else
            {

                Write-CHLog -Function 'Check BITS Queue' -Message 'Remediation is disabled, logging BITS queue.'
                $null = Clear-BITSQueue -logonly
                Write-CHLog -Function 'Check BITS Queue' -Message 'Remediation is disabled, logging BITS queue complete.'
            }

            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastDate' -Data (Get-Date -format yyyy-MM-dd) -DataType 'string'
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastTime' -Data (Get-Date -format HH:mm:ss) -DataType 'string'
        }

        ###############################################################################
        #   Install Client
        ###############################################################################

        if($SCCMClientRepair){ Invoke-CHClientAction -Action Repair }
        else
        {
            #get the number of free MB on drive system drive
            [int]$DriveCFreeMB = Get-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_CFreeSpace'
            
            if(($script:SCCMInstalled -eq $false) -and $DriveCFreeMB -ge 512 -and $WMIHealth -eq $true)
            {
                $null = Invoke-CHClientAction -Action Install
            }
            elseif($WMIHealth -eq $false)
            {
                Write-CHLog -Function 'Main.InstallClient' -Message 'Warning - Client will not be installed due to WMI being unhealthy'
                Write-CHEventLog -Function 'Main.InstallClient' -Message 'Warning - Client will not be installed due to WMI being unhealthy' -IDType Error -Enabled $script:ClientSettings.EventLog
            }
            elseif($DriveCFreeMB -le 512)
            {
                Write-CHLog -Function 'Main.InstallClient' -Message 'Error - Client will not be installed due drive space requirements'
                Write-CHEventLog -Function 'Main.InstallClient' -Message 'Error - Client will not be installed due drive space requirements' -IDType Error -Enabled $script:ClientSettings.EventLog
            }
            else
            {
                Write-CHLog -Function 'Main.InstallClient' -Message 'Client is already installed'
            }
        }

        if($script:ClientSettings.ACPService -eq $True -and $ACPInstall)
        {
            Invoke-CHACPInstall -ACPSetup $script:ClientSettings.ACPInstallCmd -ACPServiceName $script:ClientSettings.ACPServiceName -ACPArguments $script:ClientSettings.ACPInstallArgs
        }

        if($script:SCCMInstalled)
        {
            [string]$SCCMGUID = Get-CHini -File "$env:windir\smscfg.ini" -Section 'Configuration - Client Properties' -Key 'SMS Unique Identifier'
        }

        ###############################################################################
		#   Check if the currently assigned SCCM site is correct
		###############################################################################
		If ($SCCMInstalled)
		{
			Test-SMSAssignedSite
		}

		###############################################################################
		#   Check if the currently assigned PFE site is correct
		###############################################################################
		If ($OSType -ne "server")
		{
			Test-PFEAssignedSite
		}

        ###############################################################################
        #   Update ConfigMgr Client Remediation Registry
        ###############################################################################

        if($ADSite -ne '') { Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'AD Site Name' -Data $ADSite -DataType 'string' }
        else{ Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'AD Site Name' -Data 'NO AD SITE ASSIGNED' -DataType 'string' }
        If($SCCMGUID) {Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'SMS Unique Identifier' -Data $SCCMGUID -DataType 'string'}
        Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'Agent Name' -Data $AgentName -DataType 'string'
        Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'Agent Site' -Data $script:SiteCode -DataType 'string'
        Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'Netbios Name' -Data ($env:COMPUTERNAME) -DataType 'string'
        Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastAction' -Data 'Update Registry' -DataType 'string'
        Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastDate' -Data (Get-Date -format yyyy-MM-dd) -DataType 'string'
        Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastTime' -Data (Get-Date -format HH:mm:ss) -DataType 'string'

      #endregion #################################### END MAIN LOGIC ####################################>

#region ############################### CREATE CLIENT REMEDIATION XML #############################>

        ###############################################################################
        #   Write ConfigMgr Client Remediation XML
        ###############################################################################

        if($script:ClientSettings.CreateXML -eq $True)
        {
            Write-CHLog -Function 'Main.WriteXML' -Message 'Beginning creation of XML to report remediation status'
            Write-CHEventLog -Function 'Main.WriteXML' -Message 'Beginning creation of XML to report remediation status' -IDType Info -Enabled $script:ClientSettings.EventLog 

            #
            #Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastAction' -Data 'Create XML' -DataType 'string'
            #
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastDate' -Data (Get-Date -format yyyy-MM-dd) -DataType 'string'
            Set-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastTime' -Data (Get-Date -format HH:mm:ss) -DataType 'string'

            Try
            {
        
            [xml]$pfexml = @" 
<?xml version="1.0" encoding="UTF-8"?>
<DDR>
   <Property Name="SiteCode" Value="$script:SiteCode" Type="String"/>
   <Property Name="Name" Value="$env:COMPUTERNAME" Type="String"/>
   <Property Name="SMS Unique Identifier" Value="$SCCMGUID" Type="String"/>
   <Property Name="NetBIOS Name" Value="$env:COMPUTERNAME" Type="String"/>
   <Property Name="PFE_ScriptVer" Value="$ScriptVersion" Type="String"/>
   <Property Name="PFE_LastAction" Value="$(Get-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_LastAction')" Type="String"/>
   <Property Name="PFE_LastDate" Value="$((Get-Date -format yyyy-MM-dd).ToString())" Type="String"/>
   <Property Name="PFE_LastTime" Value="$((Get-Date -format HH:mm:ss).ToString())" Type="String"/>
   <Property Name="PFE_BITSStatus" Value="$BITSHealth" Type="String"/>
   <Property Name="PFE_BITSQueue" Value="$BITSQueue" Type="String"/>
   <Property Name="PFE_WUAStatus" Value="$WUAHealth" Type="String"/>
   <Property Name="PFE_WMIStatus" Value="$WMIService" Type="String"/>
   <Property Name="PFE_CCMStatus" Value="$CCMHealth" Type="String"/>
   <Property Name="PFE_WMIReadRepository" Value="$WMIReadRepository" Type="String"/>
   <Property Name="PFE_WMIWriteRepository" Value="$WMIWriteRepository" Type="String"/>
   <Property Name="PFE_DCOM" Value="$DCOMHealth" Type="String"/>
   <Property Name="PFE_DCOMProtocols" Value="$DCOMProtocolHealth" Type="String"/>
   <Property Name="PFE_RebootPending" Value="$PFEReboot" Type="String"/>
   <Property Name="PFE_CFreeSpace" Value="$($SystemDriveMBFree.ToString())" Type="Integer"/>
   <Property Name="PFE_StaleLogs" Value="$StaleLogFiles" Type="String"/>
   <Property Name="PFE_WMIRebuildAttempts" Value="$(Get-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_WMIRebuildAttempts')" Type="Integer"/>
   <Property Name="PFE_ClientInstallCount" Value="$(Get-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_ClientInstallCount')" Type="Integer"/>
   <Property Name="PFE_PolicyPlatformLAStatus" Value="$PPLAHealth" Type="String"/>
   <Property Name="PFE_PolicyPlatformProcessorStatus" Value="$PPPHealth" Type="String"/>
   <Property Name="PFE_ACPStatus" Value="$ACPHealth" Type="String"/>
   <Property Name="PFE_LanternAppCI" Value="$LanternAppCI" Type="String"/>
   <Property Name="PFE_HardwareInventoryDate (UTC)" Value="$(Get-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_HWINVDate (UTC)')" Type="String"/>
   <Property Name="PFE_SoftwareInventoryDate (UTC)" Value="$(Get-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_SWINVDate (UTC)')" Type="String"/>
   <Property Name="PFE_HeartbeatDate (UTC)" Value="$(Get-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_HeartbeatDate (UTC)')" Type="String"/>
   <Property Name="PFE_ProvisioningMode" Value="$ProvisioningMode" Type="String"/>
   <Property Name="PFE_Remediation" Value="$(Get-CHRegistryValue -RegKey $script:PFEKeyPath -RegValue 'PFE_Remediation')" Type="String"/>
</DDR>
"@
              #$pfexml.ddr.property
              # Saving the XML
              $pfexml.Save(('{0}\{1}.xml' -f $script:CurrentLocation, ($env:COMPUTERNAME)))
       
                #Check for service stopped or not installed; copy to share or HTTP upload of true
                Try
                {
                    [object]$PFEService = Get-Service -Name PFERemediation -ErrorAction Stop
                    if($PFEService.Status -ne 'Running' -or $Register -eq 0 -or $script:ClientSettings.HTTPXML -eq $True) 
                    {
                        [bool]$Upload = $True
                    }
                    else
                    {
                        [bool]$Upload = $False
                    }
                }
                Catch
                {
                    #if no service, copy file to network share
                    [bool]$Upload = $True
                }

                if($Upload)
                {
 
                    if($script:ClientSettings.HTTPXML -eq $True)
                    {
                                
                        if($script:Debug) { Write-CHLog -Function 'Main' -Message 'Sending the XML via HTTP Service' }
                        $null = Send-CHHttpXML -XMLFile ('{0}\{1}.xml' -f $script:CurrentLocation, $($env:COMPUTERNAME)) -SiteServer $script:ClientSettings.PrimarySiteURL
                    }
                    else
                    {
                        if($script:Debug) { Write-CHLog -Function 'Main' -Message 'Copying XML to Network Share; validating share path exists' }
                        if(Test-Path -Path ('\\{0}\PFEIncoming$' -f $($script:ClientSettings.primarySiteServer)))
                        {
                            if($script:Debug) { Write-CHLog -Function 'Main' -Message ('Share path \\{0}\PFEIncoming$ exists; copying XML to Network Share' -f $($script:ClientSettings.primarySiteServer)) }

                            Try
                            {
                                Copy-Item -Path ('{0}\{1}.xml' -f $script:CurrentLocation, ($env:COMPUTERNAME)) -Destination ('\\{0}\PFEIncoming$' -f $($script:ClientSettings.primarySiteServer)) -ErrorAction Stop

                                if($script:Debug) { Write-CHLog -Function 'Main' -Message 'Successfully copied XML to network share' }
                            }
                            Catch
                            {
                                [string]$ErrorMsg = ($Error[0].toString()).Split('.')[0]
                                Write-CHLog -Function 'Main' -Message ('Error - Copy to \\{0}\PFEIncoming$ failed with error {1}' -f $($script:ClientSettings.primarySiteServer), $ErrorMsg)
                                Write-CHEventLog -Function 'Main' -Message ('Error - Copy to \\{0}\PFEIncoming$ failed with error {1}' -f $($script:ClientSettings.primarySiteServer), $ErrorMsg) -IDType Error -Enabled $script:ClientSettings.EventLog
                            }
                        }
                        else
                        {
                            Write-CHLog -Function 'Main' -Message ('Error - PFEIncoming$ share is not accessible on {0}' -f $($script:ClientSettings.primarySiteServer))
                            Write-CHEventLog -Function 'Main' -Message ('Error - PFEIncoming$ share is not accessible on {0}' -f $($script:ClientSettings.primarySiteServer)) -IDType Error -Enabled $script:ClientSettings.EventLog
                        }
                    }
                }
                else
                { 
                    if($script:Debug) 
                    {

                        Write-CHLog -Function 'Main' -Message 'Not copying XML as PFE Service will perform this action on next cycle' 
                        Write-CHEventLog -Function 'Main' -Message 'Not copying XML as PFE Service will perform this action on next cycle' -IDType Info -Enabled $script:ClientSettings.EventLog

                    } 
                }
            }
            Catch
            {
                #capture error message and log
                [string]$ErrorMsg = ($Error[0].toString()).Split('.')[0]
                Write-CHLog -Function 'Main' -Message ('Error - failed to create XML object: {0}' -f $ErrorMsg)
                Write-CHEventLog -Function 'Main' -Message ('Error - failed to create XML object: {0}' -f $ErrorMsg) -IDType Error -Enabled $script:ClientSettings.EventLog

            }
        }
        else
        {
            Write-CHLog -Function 'Main' -Message 'NO ACTION TAKEN: CreateXML value is false or the property was not found.'
            Write-CHEventLog -Function 'Main' -Message 'NO ACTION TAKEN: CreateXML value is false or the property was not found.' -IDType Error -Enabled $script:ClientSettings.EventLog
        }
    }
    else
    {
        Write-CHLog -Function 'Main' -Message 'NO ACTION TAKEN: The Task Sequence Manager is running; not continuing to remediate SCCM client.'
        Write-CHEventLog -Function 'Main' -Message 'NO ACTION TAKEN: The Task Sequence Manager is running; not continuing to remediate SCCM client.' -IDType Error -Enabled $script:ClientSettings.EventLog
    }
}
else
{
    Write-CHLog -Function 'Main' -Message 'NO ACTION TAKEN: The script is not running as an administrator'
    Write-CHEventLog -Function 'Main' -Message 'NO ACTION TAKEN: The script is not running as an administrator' -IDType Error -Enabled $script:ClientSettings.EventLog
}

Write-CHLog -Function 'Main' -Message 'PFE Client Remediation Script Completed'

#endregion #################################### END MAIN LOGIC ####################################>