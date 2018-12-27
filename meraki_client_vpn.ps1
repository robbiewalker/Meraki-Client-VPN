# Create Meraki Client VPN
# 20181226 RJW
#
# This script will create a split-tunnel VPN connection to a Meraki MX.
# This script was tested on Windows 10 up to date at Christmas 2018.
#
# It will add RFC1918 private address space routes to that VPN and
# add DNS suffix triggers and dns servers to that connection as well as make
# it a trusted network.
#
# You must run this powershell script from a "Run As Administrator"
# powershell session
#
# Unless the default for scripts has changed, you cannot run a powershell
# script on most Windows installations without first expressly setting the
# Execution Policy
#
# To do that use the following commands interactively from the powershell:
#
# Get-ExecutionPolicy
# 
# This will show you what your current execution policy is.
# If it's Remote Signed, Unrestricted or Bypass you should be fine
# If not, the following command will change it for your session:
#
# Set-ExecutionPolicy -Scope Process -ExecutionPolicy Unrestricted
#
# This will the change the execution policy temporarily (safest) for just
# the shell you type the above command in. Then you should be able to
# run this script, i.e. .\meraki_client_vpn.ps1
#
##############################################################################

# Variable Definitions - You can change to suit your specific needs but the
# script asks for most of them as input. Just hit enter to accept the defaults
# listed here. Obviously the preshared key isn't going to be defaulted. You 
# probably shouldn't change anything else unless you know what you are doing.
# You have been warned.

# The name of the VPN connection to be created.
[string] $VPN_NAME = "Meraki L2TP VPN"

# The FQDN or IP of the VPN Server.
[string] $SERVER_ADDRESS = ""

# The preshared key for the VPN Connection
[string] $PRESHARED_KEY

# The DNS Suffix (domain) of the VPN connection.
[string] $DNS_SUFFIX = ""

# The array of DNS server addresses for this connection.
[string[]] $DNS_IP_ADDRESS = @("8.8.8.8", "1.1.1.1")

[string[]] $ROUTES_TO_ADD = @("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
[Int32] $ROUTE_METRIC = 200

$DEBUG = 0
$RASFILE = ((Get-Item env:APPDATA).Value + "\Microsoft\Network\Connections\Pbk\rasphone.pbk")

##############################################################################
##############################################################################
Write-Output "Type new values below or hit ENTER or RETURN to accept the [defaults]...`n"
$NAME = Read-Host -Prompt ("Please type the name of new VPN Connection             [" + $VPN_NAME + "]")
$FQDN = Read-Host -Prompt ("Please type the FQDN or IP of the server             [" + $SERVER_ADDRESS + "]")
# If you went to the trouble of adding the preshared key into the script,
# we'll just skip the whole asking for it bit...
if ([String]::IsNullOrWhiteSpace($PRESHARED_KEY)) {
    $LOOPCOUNT = 0
    do {
        $LOOPCOUNT = $LOOPCOUNT + 1
        $PRESHARED_KEY_SS = Read-Host -AsSecureString -Prompt "Please enter the VPN preshared key                  "
        $SSPOINTER = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($PRESHARED_KEY_SS)
        $PRESHARED_KEY = [Runtime.InteropServices.Marshal]::PtrToStringAuto($SSPOINTER)
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($SSPOINTER)
        if ( [String]::IsNullOrWhiteSpace($PRESHARED_KEY)) {
            Write-Output "`nPreshared key is empty. That's almost certainly wrong.`n"
        }
        else {
            $LOOPCOUNT = 3
        }
    } until ($LOOPCOUNT -gt 2)
}
$SUFF = Read-Host -Prompt ("VPN network DNS Suffix (domain)                              [" + $DNS_SUFFIX + "]")
$DNS  = Read-Host -Prompt ("DNS Servers separated with a space               [" + ($DNS_IP_ADDRESS -Join(" ")) + "]")
$NETS = Read-Host -Prompt ("Route subnets separated with a space [" + ($ROUTES_TO_ADD -Join(" ")) + "]")
$METR = Read-Host -Prompt ("Metric for added routes                                                  [" + $ROUTE_METRIC.ToString() + "]")

if (! [String]::IsNullOrWhiteSpace($NAME)) { $VPN_NAME = $NAME}
if (! [String]::IsNullOrWhiteSpace($FQDN)) { $SERVER_ADDRESS = $FQDN}
if (! [String]::IsNullOrWhiteSpace($SUFF)) { $DNS_SUFFIX = $SUFF}
if (! [String]::IsNullOrWhiteSpace($DNS))  { $DNS_IP_ADDRESS = $DNS.Split(" ")}
if (! [String]::IsNullOrWhiteSpace($NETS)) { $ROUTES_TO_ADD = $NETS.Split(" ")}
if (! [String]::IsNullOrWhiteSpace($METR)) { $ROUTE_METRIC = $METR.ToInt32()}

Write-Output "`nReview`n======================================"
Write-Output "         Name: $VPN_NAME"
Write-Output "       Server: $SERVER_ADDRESS"
if ($DEBUG) {
    Write-Output "Preshared Key: $PRESHARED_KEY"
} else {
    Write-Output "Preshared Key: ****************"
}
Write-Output "   DNS Suffix: $DNS_SUFFIX"
Write-Output ("  DNS Servers: " + ($DNS_IP_ADDRESS -Join(", ")))
Write-Output ("       Routes: " + ($ROUTES_TO_ADD -Join(", ")))
Write-Output " Route Metric: $ROUTE_METRIC"
Write-Output ""
$PROCEED = Read-Host -Prompt "Type y or Y and hit ENTER or RETURN to proceed"
if (! ($PROCEED -ilike "y")) {
    Exit-PSHostProcess
}
# Microsoft seems to have disabled NAT-T for some reason.
# The following registry key re-enables it, but a system restart is necessary.
# The script will check for the existence of the name/value pair as well as
# the actual value of the value name. ( 2 in this case. )
#
# For reference this key is non-existent on a default installation of Windows 10
# So remove the key value if you want to go back to the default settings.
$NATTREG = 0
try {
    $NATTREG = Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PolicyAgent" -Name "AssumeUDPEncapsulationContextOnSendRule" -ErrorAction Stop
}
catch {
    Write-Output "The registry key [HKEY Local Machine\SYSTEM\CurrentControlSet\Services\PolicyAgent] does not have an 'AssumeUDPEncapsulationContextOnSendRule' value.`n" + $Error[0].Message.ToString()
}
finally {
    # NOTE: This is not wrapped in a try-catch as if it fails we want the script to stop. Something is wrong.
    if ( $NATTREG -ne 2 ) {
        Write-Warning -Message "Since the value of registry key [HKEY Local Machine\SYSTEM\CurrentControlSet\Services\PolicyAgent:AssumeUDPEncapsulationContextOnSendRule] is not 2, we will set it to 2 and you will need to restart the computer."
        Write-Output "Note: default Windows 10 installations do not have this registry key value at all, so this is normal the first time this script is run."
        Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\PolicyAgent -Name AssumeUDPEncapsulationContextOnSendRule -Value (2).ToInt32() -Type DWord -ErrorAction Stop -Confirm
    }
}

# The sharp end of the script
Add-VpnConnection -Name $VPN_NAME -ServerAddress $SERVER_ADDRESS -TunnelType L2tp -DnsSuffix $DNS_SUFFIX -SplitTunneling -EncryptionLevel Optional -L2tpPsk $PRESHARED_KEY -AuthenticationMethod Pap -RememberCredential -Force
foreach ($SUBNET in $ROUTES_TO_ADD) {
    Add-VpnConnectionRoute -ConnectionName $VPN_NAME -DestinationPrefix $SUBNET -RouteMetric $ROUTE_METRIC
}
Add-VpnConnectionTriggerDnsConfiguration -ConnectionName $VPN_NAME -DnsSuffix $DNS_SUFFIX -DnsIPAddress $DNS_IP_ADDRESS
Add-VpnConnectionTriggerTrustedNetwork -ConnectionName $VPN_NAME -DnsSuffix $DNS_SUFFIX

# The below command will turn off class based default routes in all
# RAS connections. I have no idea why Microsoft still has class based 
# network routing. It hasn't been used in over 30 years...
(Get-Content $RASFILE) -replace 'DisableClassBasedDefaultRoute=0', 'DisableClassBasedDefaultRoute=1' | Set-Content $RASFILE
Write-Output "Finished. If the registry had to be updated for NAT-T you may need to restart."
