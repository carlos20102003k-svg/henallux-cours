scan.ps1
	<#
	.SYNOPSIS
	Discover live hosts in a subnet using ICMP (ping).
	
	.DESCRIPTION
	Accepts a subnet in CIDR notation (like 192.168.1.0/24) and pings every address in that subnet.
	Works with PowerShell 7+ for parallel scanning (much faster). On Windows PowerShell 5.1 it uses a sequential method.
	.PARAMETER Cidr
	Subnet in CIDR form, e.g. 192.168.1.0/24
	.PARAMETER TimeoutMs
	Ping timeout in milliseconds (default 1000)
	.PARAMETER MaxParallel
	Maximum parallel threads when running in PowerShell 7+ (default 100)
	.PARAMETER ExcludeNetworkBroadcast
	If True (default), excludes network and broadcast addresses from the scan when applicable.
	.PARAMETER OutCsv
	Optional filepath to export responsive IPs to CSV.
	.EXAMPLE
	.\Find-LiveHosts.ps1 -Cidr 192.168.1.0/24 -TimeoutMs 500 -OutCsv C:\temp\livehosts.csv
	#>
	
	param(
	[Parameter(Mandatory=$true)]
	[string]$Cidr,
	
	[int]$TimeoutMs = 1000,
	
	[int]$MaxParallel = 100,
	
	[bool]$ExcludeNetworkBroadcast = $true,
	
	[string]$OutCsv
	)
	
	function Convert-CidrToIPRange {
		param(
		[Parameter(Mandatory=$true)] [string]$Cidr
		)
		# Validate and split
		if ($Cidr -notmatch '^([0-9]{1,3}\.){3}[0-9]{1,3}\/([0-9]|[12][0-9]|3[0-2])$') {
			throw "CIDR must be in form x.x.x.x/nn (0-32). Received: $Cidr"
		}
		$parts = $Cidr.Split('/')
		$ipStr = $parts[0]
		$prefix = [int]$parts[1]
		
		[byte[]]$ipBytes = $ipStr.Split('.') | ForEach-Object {[byte][int]$_}
		$ipInt = ([BitConverter]::ToUInt32([byte[]]($ipBytes[3], $ipBytes[2], $ipBytes[1], $ipBytes[0]), 0))
		
		$mask = [uint32]::MaxValue -shr $prefix -bxor [uint32]::MaxValue
		# Another way: $mask = ([uint32]((0xFFFFFFFF) -shr $prefix)) -bxor 0xFFFFFFFF  -> above is simpler
		
		$network = $ipInt -band $mask
		$broadcast = $network -bor (-bnot $mask -band 0xFFFFFFFF)
		
		return @{
			Network = $network
			Broadcast = $broadcast
			Mask = $mask
			Prefix = $prefix
		}
	}
	
	function UInt32ToIPv4 {
		param([uint32]$u)
		# Turn little-endian ordering appropriate for .NET BitConverter
		$b0 = ($u -shr 24) -band 0xFF
		$b1 = ($u -shr 16) -band 0xFF
		$b2 = ($u -shr 8) -band 0xFF
		$b3 = $u -band 0xFF
		return "$b0.$b1.$b2.$b3"
	}
	
	# Prepare range
	try {
		$range = Convert-CidrToIPRange -Cidr $Cidr
	} catch {
		Write-Error $_.Exception.Message; exit 1
	}
	
	$network = [uint32]$range.Network
	$broadcast = [uint32]$range.Broadcast
	$prefix = $range.Prefix
	
	# Decide the start and end addresses
	$start = $network
	$end = $broadcast
	
	if ($ExcludeNetworkBroadcast -and ($prefix -lt 31)) {
		# exclude network and broadcast for subnets with at least 2 host addresses
		$start = $start + 1
		$end = $end - 1
	}
	
	$total = [int]($end - $start + 1)
	Write-Host "Scanning $Cidr (`"$($total)`" addresses) -- Timeout: ${TimeoutMs}ms" -ForegroundColor Green
	
	# Create an array of IPs to test
	$ips = for ($i = $start; $i -le $end; $i++) {
		UInt32ToIPv4 -u $i
	}
	
	# Function to ping one IP (uses System.Net.NetworkInformation.Ping for consistent control)
	function Test-IpAlive {
		param(
		[string]$ip,
		[int]$timeoutMs
		)
		try {
			$ping = New-Object System.Net.NetworkInformation.Ping
			$reply = $ping.Send($ip, $timeoutMs)
			if ($reply -and $reply.Status -eq 'Success') {
				return @{
					IP = $ip
					RoundtripMs = $reply.RoundtripTime
				}
			} else {
				return $null
			}
		} catch {
			return $null
		}
	}
	
	# Choose parallel vs sequential behavior depending on PS edition
	$responsive = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
	
	if ($PSVersionTable.PSVersion.Major -ge 7) {
		# Use ForEach-Object -Parallel (PowerShell 7+). Limit degree of parallelism.
		$scriptBlock = {
			param($ip, $timeout)
			try {
				$ping = New-Object System.Net.NetworkInformation.Ping
				$reply = $ping.Send($ip, $timeout)
				if ($reply -and $reply.Status -eq 'Success') {
					[PSCustomObject]@{
						IP = $ip
						RoundtripMs = $reply.RoundtripTime
					}
				} else {
					$null
				}
			} catch {
				$null
			}
		}
		
		$throttle = [int]$MaxParallel
		$found = $ips | ForEach-Object -Parallel $scriptBlock -ArgumentList $TimeoutMs -ThrottleLimit $throttle
		$found = $found | Where-Object { $_ -ne $null } | Sort-Object {[System.Net.IPAddress]::Parse($_.IP).GetAddressBytes() -join '.'}
		$responsive = $found
	} else {
		# Sequential fallback (compatibility for Windows PowerShell 5.1)
		foreach ($ip in $ips) {
			$result = Test-IpAlive -ip $ip -timeoutMs $TimeoutMs
			if ($result) { $responsive.Add((New-Object PSObject -Property $result)) }
		}
		# convert concurrentbag to array and sort
		$responsive = $responsive.ToArray() | Sort-Object {[System.Net.IPAddress]::Parse($_.IP).GetAddressBytes() -join '.'}
	}
	
	# Display results
	if (-not $responsive -or $responsive.Count -eq 0) {
		Write-Host "No responsive hosts found (ICMP may be blocked)." -ForegroundColor Yellow
	} else {
		$table = $responsive | Select-Object IP, RoundtripMs
		$table | Format-Table -AutoSize
		
		if ($OutCsv) {
			try {
				$table | Export-Csv -Path $OutCsv -NoTypeInformation -Force
				Write-Host "Results exported to $OutCsv" -ForegroundColor Green
			} catch {
				Write-Warning "Failed to export CSV: $($_.Exception.Message)"
			}
		}
	}
