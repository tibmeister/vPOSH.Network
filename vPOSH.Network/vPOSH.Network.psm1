<#
    .SYNOPSIS
        Various netowkr related functions for vSphere
#>

function Get-VmByMacAddress
{
    <#
    .SYNOPSIS
        [PowerCLI]Retrieves the virtual machines with a certain MAC address.

    .DESCRIPTION
        Retrieves the virtual machines with a certain MAC address on all connect vCenters.

    .PARAMETER MacAddress
        Specify the MAC address of the virtual machines to search for.

    .EXAMPLE
        Get-VmByMacAddress -MacAddress 00:0c:29:1d:5c:ec,00:0c:29:af:41:5c
        Retrieves the virtual machines with MAC addresses 00:0c:29:1d:5c:ec and 00:0c:29:af:41:5c.

    .EXAMPLE
        "00:0c:29:1d:5c:ec","00:0c:29:af:41:5c" | Get-VmByMacAddress
        Retrieves the virtual machines with MAC addresses 00:0c:29:1d:5c:ec and 00:0c:29:af:41:5c.
    #>

    [CmdletBinding()]
    param(
        [parameter(Mandatory = $true,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true)]
        [string[]] $MacAddress
    )

    begin
    {
        # $Regex contains the regular expression of a valid MAC address
        $Regex = "^[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]$"

        # Get all the virtual machines
        $VMsView = Get-View -ViewType VirtualMachine -Property Name,Guest.Net
    }

    process
    {
        ForEach ($Mac in $MacAddress)
        {
            # Check if the MAC Address has a valid format
            if ($Mac -notmatch $Regex)
            {
                Write-Error "$Mac is not a valid MAC address. The MAC address should be in the format 99:99:99:99:99:99."
            }
            else
            {
                # Get all the virtual machines
                $VMsView | `
                ForEach-Object {
                    $VMview = $_
                    $VMView.Guest.Net | Where-Object {
                    # Filter the virtual machines on Mac address
                    $_.MacAddress -eq $Mac
                    } | `
                    Select-Object -property @{N="VM";E={$VMView.Name}},
                        MacAddress,
                        IpAddress,
                        Connected
                }
            }
        }
    }
}

function Get-SubnetInformation {
	<#
		.SYNOPSIS
			Calculates the IP subnet information based upon the entered IP address and subnet.
		.DESCRIPTION
			Calculates the IP subnet information based upon the entered IP address and subnet. It can accept both CIDR and dotted decimal formats.
		.PARAMETER IPAddress
			Enter the IP address by itself or with CIDR notation.
		.PARAMETER Netmask
			Enter the subnet mask information in dotted decimal form.
		.PARAMETER IncludeTextOutput
			Include a text output of the subnet information in ipcalc.pl similar format.
		.PARAMETER IncludeBinaryOutput
			Include the binary format of the subnet information.
		.EXAMPLE
			Get-SubnetInformation -IPAddress 10.100.100.1 -NetMask 255.255.255.0

			Address   : 10.100.100.1
			Netmask   : 255.255.255.0
			Wildcard  : 0.0.0.255
			Network   : 10.100.100.0/24
			Broadcast : 10.100.100.255
			HostMin   : 10.100.100.1
			HostMax   : 10.100.100.254
			Hosts/Net : 254

		.EXAMPLE
			Get-SubnetInformation 10.10.100.5/24

			Address   : 10.10.100.5
			Netmask   : 255.255.255.0
			Wildcard  : 0.0.0.255
			Network   : 10.10.100.0/24
			Broadcast : 10.10.100.255
			HostMin   : 10.10.100.1
			HostMax   : 10.10.100.254
			Hosts/Net : 254

		.EXAMPLE
			Get-SubnetInformation 192.168.0.1/24 -IncludeBinaryOutput

			Address         : 192.168.0.1
			Netmask         : 255.255.255.0
			Wildcard        : 0.0.0.255
			Network         : 192.168.0.0/24
			Broadcast       : 192.168.0.255
			HostMin         : 192.168.0.1
			HostMax         : 192.168.0.254
			Hosts/Net       : 254
			AddressBinary   : 11000000101010000000000000000001
			NetmaskBinary   : 11111111111111111111111100000000
			WildcardBinary  : 00000000000000000000000011111111
			NetworkBinary   : 11000000101010000000000000000000
			HostMinBinary   : 11000000101010000000000000000001
			HostMaxBinary   : 11000000101010000000000011111110
			BroadcastBinary : 11000000101010000000000011111111

		#>

		[CmdletBinding()]
		param
		(
			[Parameter(Mandatory=$True,Position=1)]
			[string]$IPAddress,

			[Parameter(Mandatory=$False,Position=2)]
			[string]$Netmask,

			[switch]$IncludeTextOutput,

			[switch]$IncludeBinaryOutput
		)

	# Check to see if the IP Address was entered in CIDR format.
	if ($IPAddress -like "*/*")
	{
		$CIDRIPAddress = $IPAddress
		$IPAddress = $CIDRIPAddress.Split("/")[0]
		$cidr = [convert]::ToInt32($CIDRIPAddress.Split("/")[1])
		if ($cidr -le 32 -and $cidr -ne 0)
		{
			$ipBinary = toBinary $IPAddress
			Write-Verbose $ipBinary
			$smBinary = CidrToBin($cidr)
			Write-Verbose $smBinary
			$Netmask = toDottedDecimal($smBinary)
			$wildcardbinary = NetMasktoWildcard ($smBinary)
		}
		else
		{
			Write-Warning "Subnet Mask is invalid!"
			Exit
		}
	}
	else
		{
		if (!$Netmask)
		{
			$Netmask = Read-Host "Netmask"
		}
		$ipBinary = toBinary $IPAddress
		if ($Netmask -eq "0.0.0.0")
		{
			Write-Warning "Subnet Mask is invalid!"
			Exit
		}
		else
		{
			$smBinary = toBinary $Netmask
			$wildcardbinary = NetMasktoWildcard ($smBinary)
		}
	}


	# First determine the location of the first zero in the subnet mask in binary (if any)
	$netBits=$smBinary.indexOf("0")

	# If there is a 0 found then the subnet mask is less than 32 (CIDR).
	if ($netBits -ne -1)
	{
		$cidr = $netBits
		#validate the subnet mask
		if(($smBinary.length -ne 32) -or ($smBinary.substring($netBits).contains("1") -eq $true))
		{
			Write-Warning "Subnet Mask is invalid!"
			Exit
		}

		# Validate the IP address
		if($ipBinary.length -ne 32)
		{
			Write-Warning "IP Address is invalid!"
			Exit
		}

		#identify subnet boundaries
		$networkID = toDottedDecimal $($ipBinary.substring(0,$netBits).padright(32,"0"))
		$networkIDbinary = $ipBinary.substring(0,$netBits).padright(32,"0")
		$firstAddress = toDottedDecimal $($ipBinary.substring(0,$netBits).padright(31,"0") + "1")
		$firstAddressBinary = $($ipBinary.substring(0,$netBits).padright(31,"0") + "1")
		$lastAddress = toDottedDecimal $($ipBinary.substring(0,$netBits).padright(31,"1") + "0")
		$lastAddressBinary = $($ipBinary.substring(0,$netBits).padright(31,"1") + "0")
		$broadCast = toDottedDecimal $($ipBinary.substring(0,$netBits).padright(32,"1"))
		$broadCastbinary = $ipBinary.substring(0,$netBits).padright(32,"1")
		$wildcard = toDottedDecimal ($wildcardbinary)
		$Hostspernet = ([convert]::ToInt32($broadCastbinary,2) - [convert]::ToInt32($networkIDbinary,2)) - 1
	}
	else
	{
		# Validate the IP address
		if($ipBinary.length -ne 32)
		{
			Write-Warning "IP Address is invalid!"
			Exit
		}

		#identify subnet boundaries
		$networkID = toDottedDecimal $($ipBinary)
		$networkIDbinary = $ipBinary
		$firstAddress = toDottedDecimal $($ipBinary)
		$firstAddressBinary = $ipBinary
		$lastAddress = toDottedDecimal $($ipBinary)
		$lastAddressBinary = $ipBinary
		$broadCast = toDottedDecimal $($ipBinary)
		$broadCastbinary = $ipBinary
		$wildcard = toDottedDecimal ($wildcardbinary)
		$Hostspernet = 1
		$cidr = 32
	}

	#region Output

	# Include a ipcalc.pl style text output (not an object)
	if ($IncludeTextOutput)
	{
		Write-Host "`nAddress:`t`t$IPAddress"
		Write-Host "Netmask:`t`t$Netmask = $cidr"
		Write-Host "Wildcard:`t`t$wildcard"
		Write-Host "=>"
		Write-Host "Network:`t`t$networkID/$cidr"
		Write-Host "Broadcast:`t`t$broadCast"
		Write-Host "HostMin:`t`t$firstAddress"
		Write-Host "HostMax:`t`t$lastAddress"
		Write-Host "Hosts/Net:`t`t$Hostspernet`n"
	}

	# Output custom object with or without binary information.
	if ($IncludeBinaryOutput)
	{
		New-Object PSObject -Property @{
			Address = $IPAddress
			Netmask = $Netmask
			Wildcard = $wildcard
			Network = "$networkID/$cidr"
			Broadcast = $broadCast
			HostMin = $firstAddress
			HostMax = $lastAddress
			'Hosts/Net' = $Hostspernet
			AddressBinary = $ipBinary
			NetmaskBinary = $smBinary
			WildcardBinary = $wildcardbinary
			NetworkBinary = $networkIDbinary
			HostMinBinary = $firstAddressBinary
			HostMaxBinary = $lastAddressBinary
			BroadcastBinary = $broadCastbinary
		}
	}
	else
	{
		New-Object PSObject -Property @{
			Address = $IPAddress
			Netmask = $Netmask
			Wildcard = $wildcard
			Network = "$networkID/$cidr"
			Broadcast = $broadCast
			HostMin = $firstAddress
			HostMax = $lastAddress
			'Hosts/Net' = $Hostspernet
		}
	}
}

# Function to convert IP address string to binary
function toBinary
{
	param
	(
		$dottedDecimal
	)

	$dottedDecimal.split(".") | ForEach-Object {$binary=$binary + $([convert]::toString($_,2).padleft(8,"0"))}
 	return $binary
}

# Function to binary IP address to dotted decimal string
function toDottedDecimal ($binary){
    do {$dottedDecimal += "." + [string]$([convert]::toInt32($binary.substring($i,8),2)); $i+=8 } while ($i -le 24)
    return $dottedDecimal.substring(1)
}

# Function to convert CIDR format to binary
function CidrToBin
{
	param
	(
		$cidr
	)

	if($cidr -le 32)
	{
		[Int[]]$array = (1..32)
		for($i=0;$i -lt $array.length;$i++)
		{
			if($array[$i] -gt $cidr){$array[$i]="0"}else{$array[$i]="1"}
		}
		$cidr =$array -join ""
	}
	return $cidr
}

# Function to convert network mask to wildcard format
function NetMasktoWildcard
{
	param
	(
		$wildcard
	)
	foreach ($bit in [char[]]$wildcard)
	{
		if ($bit -eq "1")
		{
			$wildcardmask += "0"
		}
		elseif ($bit -eq "0")
		{
			$wildcardmask += "1"
		}
	}
	return $wildcardmask
}

New-VIProperty -Name NetworkInfo -ObjectType VirtualMachine -Value {
                    param
                    (
                        $vm
                    )

					$vm.ExtensionData.Guest.Net | select -Property @{N='VM';E={$vm.Name}},
					@{N='NicType';E={[string]::Join(',',(Get-NetworkAdapter -Vm $vm | Select-Object -ExpandProperty Type))}},
					@{N='NetworkName';E={[string]::Join(',',(Get-NetworkAdapter -Vm $vm | Select-Object -ExpandProperty NetworkName))}},
					@{N='IP';E={[string]::Join(',',($vm.Guest.IPAddress | Where {($_.Split(".")).length -eq 4}))}},
					@{N='Gateway';E={[string]::Join(',',($vm.ExtensionData.Guest.IpStack.IpRouteConfig.IpRoute | %{if($_.Gateway.IpAddress){$_.Gateway.IpAddress}}))}},
					@{N='Subnet Mask';E={
                        $dec = [Convert]::ToUInt32($(('1' * $_.IpConfig.IpAddress[0].PrefixLength).PadRight(32, '0')), 2)
                        $DottedIP = $( For ($i = 3; $i -gt -1; $i--) {
                                    $Remainder = $dec % [Math]::Pow(256, $i)
                                    ($dec - $Remainder) / [Math]::Pow(256, $i)
                                    $dec = $Remainder
                            } )
                        [String]::Join('.', $DottedIP)
                    }},
					@{N="DNS";E={[string]::Join(',',($vm.ExtensionData.Guest.IpStack.DnsConfig.IpAddress))}},
					@{N='MAC';E={[string]::Join(',',$_.MacAddress)}}
				} -ErrorAction SilentlyContinue -Verbose:$false -WarningAction SilentlyContinue

New-VIProperty -Name VlanId -ObjectType VirtualPortGroup -Value {
	param
	(
		[VDPortGroup]$vdPG
	)

    return $vdPg.ExtensionData.Config.DefaultPortConfig.Vlan.VlanId
}