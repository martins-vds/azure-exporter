# Enable TLS 1.2 for the current PowerShell instance using the line below and try again
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
Install-Module -Name Pester -Force -SkipPublisherCheck