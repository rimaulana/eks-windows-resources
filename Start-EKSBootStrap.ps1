# Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Amazon Software License (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
# http://aws.amazon.com/asl/
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.

<#
.SYNOPSIS
EKS bootstrap script
.PARAMETER EKSClusterName
Specifies the EKS cluster name which this worker node to be joined.
.PARAMETER KubeletExtraArgs
Specifies the extra arguments for kubelet.
.PARAMETER EKSEndPointUrl
Specifies the EKS Cluster endpoint url(optional). Default is production endpoint url.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [string]$EKSClusterName,
  [string]$KubeletExtraArgs,
  [string]$EKSEndPointUrl,
  [string[]]$SNATExcludedCIDR=""
)

$ErrorActionPreference = 'STOP'

Function Get-EKSDockerRepoTag {
  <#
  .SYNOPSIS
  Gets docker repository tag for nanoserver repo
  .OUTPUTS
  Returns docker repository tag like '1809'.
  #>
  [OutputType([string])]
  param()
  $ReleaseId = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name ReleaseId).ReleaseId
  [string]$DockerRepoTag = ""

  # NanoServer repo don't have ltsc branch. Going forward, it might change.
  $DockerRepoTag = switch ($ReleaseId) {
    "1809" { "1809" }
    Default { throw [System.NotSupportedException] "$ReleaseId is not supported" }
  }

  return $DockerRepoTag
}

Function Get-EKSPauseImage {
  # ECR Pause image URI
  $PauseImageUri = '{0}.dkr.ecr.{1}.amazonaws.com/eks/pause-windows:{2}'
  
  $AvailabilityZone = Get-EC2MetaData 'latest/meta-data/placement/availability-zone'
  Write-Verbose ('Availability zone :{0}' -f $AvailabilityZone)

  $AWSRegion = $AvailabilityZone.Substring(0, $AvailabilityZone.Length-1)
  Write-Verbose ('AWS region :{0}' -f $AWSRegion)

  # PAUSE CONTAINER Account is based on regions/partitions
  Write-Verbose ('Getting Pause container account based on region')
  $PAUSE_CONTAINER_ACCOUNT = switch ($AWSRegion) {
    "ap-east-1" { "800184023465" }  # HKG
    "me-south-1" { "558608220178" } # Bahrain 
    Default { "602401143452" }      # All other regions
  }
  Write-Verbose ('EKS PAUSE Container account :{0}' -f $PAUSE_CONTAINER_ACCOUNT)

  Write-Verbose 'Getting image repo tag...'
  [string]$DockerRepoTag = Get-EKSDockerRepoTag
  Write-Verbose ('Image repo tag: {0}' -f $DockerRepoTag)
  
  Write-Verbose 'Getting EKS Pause Image...'
  $EKSPauseImage = ($PauseImageUri -f $PAUSE_CONTAINER_ACCOUNT, $AWSRegion, $DockerRepoTag)
  Write-Verbose ('EKS Pause Image: {0}' -f $ECRPath)
  
  return $EKSPauseImage
}

[string]$EKSBinDir = "$env:ProgramFiles\Amazon\EKS"
[string]$EKSDataDir = "$env:ProgramData\Amazon\EKS"
[string]$CNIBinDir = "$EKSBinDir\cni"
[string]$CNIConfigDir = "$EKSDataDir\cni\config"
[string]$IAMAuthenticator = "$EKSBinDir\aws-iam-authenticator.exe"
[string]$EKSClusterCACertFile = "$EKSDataDir\cluster_ca.crt"

[string]$KubernetesBinDir = "$env:ProgramFiles\kubernetes"
[string]$KubernetesDataDir = "$env:ProgramData\kubernetes"
[string]$Kubelet = "$KubernetesBinDir\kubelet.exe"
[string]$Kubeproxy = "$KubernetesBinDir\kube-proxy.exe"

# KUBECONFIG environment variable is set by Install-EKSWorkerNode.ps1
[string]$KubeConfigFile = [System.Environment]::GetEnvironmentVariable('KUBECONFIG', 'Machine')

# Kubelet configuration file
[string] $KubeletConfigFile = "$KubernetesDataDir\kubelet-config.json"

[string]$StartupTaskName = "EKS Windows startup task"

# Default DNS Cluster IP
[string]$global:DNSClusterIP = ""

# Default Kubernetes Service CIDR
[string]$global:ServiceCIDR = ""

# Customer VPC CIDR Range
[string[]]$global:VPCCIDRRange = ""

# Service host to host kubelet and kube-proxy
[string]$ServiceHostExe = "$EKSBinDir\EKS-WindowsServiceHost.exe"

function Get-EC2MetaData {
<#
.SYNOPSIS
Gets data from EC2 meta data
.PARAMETER Path
Specifis the path to the meta data.
.OUTPUTS
Returns meta data.
#>
  [CmdletBinding()]
  [OutputType([string])]
  param (
    [Parameter(Mandatory=$true)]
    [string]$Path
  )
  [string]$Prefix = 'http://169.254.169.254/'
  return Invoke-RestMethod -Uri ($Prefix + $Path)
}

function Update-KubeConfig {
<#
.SYNOPSIS
Creates/Updates kubeconfig file
#>
  if ($EKSEndPointUrl -ne $null) {
    $EKSCluster = Get-EKSCluster -Name $EKSClusterName -EndpointUrl $EKSEndPointUrl
  } else {
    $EKSCluster = Get-EKSCluster -Name $EKSClusterName
  }

  # Update CA certificate file
  [string]$Base64ClusterCA = $EKSCluster.CertificateAuthority.Data
  [System.Convert]::FromBase64String($Base64ClusterCA) | Set-Content -Encoding Byte $EKSClusterCACertFile

  # Update kube config file for kubelet
  [string]$APIServerEndpoint = $EKSCluster.Endpoint
  [string]$KubeConfig = @"
apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority: $EKSClusterCACertFile
    server: $APIServerEndpoint
  name: kubernetes
contexts:
- context:
    cluster: kubernetes
    user: kubelet
  name: kubelet
current-context: kubelet
users:
- name: kubelet
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1alpha1
      command: $IAMAuthenticator
      args:
        - `"token`"
        - `"-i`"
        - `"$EKSClusterName`"
"@

  Set-Content -Value $KubeConfig -Path $KubeConfigFile -Encoding ASCII
}

function Get-VPCCIDRRange {
<#
.SYNOPSIS
Returns VPC CIDR block array
#>
  [string]$EniMACAddress = Get-EC2MetaData 'latest/meta-data/mac'
  [string[]]$VPCCIDRblock = (Get-EC2MetaData "latest/meta-data/network/interfaces/macs/$EniMACAddress/vpc-ipv4-cidr-blocks").Split("`n")
  return $VPCCIDRblock;
}

function Initialize-DefaultValues {
<#
.SYNOPSIS
Initialize default values.
#>
  $global:DNSClusterIP = "10.100.0.10"
  $global:ServiceCIDR = "10.100.0.0/16"
  $global:VPCCIDRRange = Get-VPCCIDRRange
  $TenRange = $VPCCIDRRange | Where-Object {$_ -like '10.*'}

  if ($TenRange -ne $null) {
    $global:DNSClusterIP = '172.20.0.10'
    $global:ServiceCIDR = '172.20.0.0/16'
  }
}

function Update-Kubeletconfig {
<#
.SYNOPSIS
Creates & updates kubelet config file
#>
  [string]$ClientCAFile =  ConvertTo-Json $EKSClusterCACertFile

  [string]$KubeletConfig = @"
{
  "kind": "KubeletConfiguration",
  "apiVersion": "kubelet.config.k8s.io/v1beta1",
  "address": "0.0.0.0",
  "authentication": {
    "anonymous": {
      "enabled": false
    },
    "webhook": {
      "cacheTTL": "2m0s",
      "enabled": true
    },
    "x509": {
      "clientCAFile": $ClientCAFile
    }
  },
  "authorization": {
    "mode": "Webhook",
    "webhook": {
      "cacheAuthorizedTTL": "5m0s",
      "cacheUnauthorizedTTL": "30s"
    }
  },
  "clusterDomain": "cluster.local",
  "hairpinMode": "hairpin-veth",
  "cgroupDriver": "cgroupfs",
  "cgroupRoot": "/",
  "featureGates": {
    "RotateKubeletServerCertificate": true
  },
  "serializeImagePulls": false,
  "serverTLSBootstrap": true,
  "clusterDNS": [
    `"$DNSClusterIP`"
  ]
}
"@

  Set-Content -Value $KubeletConfig -Path $KubeletConfigFile -Encoding ASCII
}

function Update-EKSCNIConfig {
<#
.SYNOPSIS
Creates/Updates KES CNI plugin config file
#>
  [string]$CNIConfigFile = "$CNIConfigDir\vpc-shared-eni.conf"

  [string]$EniMACAddress = Get-EC2MetaData 'latest/meta-data/mac'
  [string]$EniIPAddress = Get-EC2MetaData 'latest/meta-data/local-ipv4'
  [string]$SubnetCIDR = Get-EC2MetaData "latest/meta-data/network/interfaces/macs/$EniMACAddress/subnet-ipv4-cidr-block"
  [string]$SubnetMaskBits = $SubnetCIDR.Split('/', 2)[1]
  [System.Collections.ArrayList]$GatewayIPAddress = (Get-NetRoute -DestinationPrefix '0.0.0.0/0').NextHop.Split("`n")

  [string[]]$DNSSuffixSearchList = ConvertTo-Json @("{%namespace%}.svc.cluster.local","svc.cluster.local","cluster.local")
  
  # Convert the VPCCIDRRange into an array
  $AllCIDRs = @($VPCCIDRRange)

  # Added the SNAT excluded CIDR for CNI VPC CIDR
  ForEach ($excluded in $SNATExcludedCIDR) {
    $AllCIDRs += $excluded
  }

  $ClusterCIDR = ConvertTo-Json $AllCIDRs

  [string]$CNIConfig = @"
{
  "cniVersion": "0.3.1",
  "name": "vpc",
  "type": "vpc-shared-eni",
  "eniMACAddress": "$EniMACAddress",
  "eniIPAddress": "$EniIPAddress/$SubnetMaskBits",
  "gatewayIPAddress": "$($GatewayIPAddress[0])",
  "vpcCIDRs": $ClusterCIDR,
  "serviceCIDR": "$ServiceCIDR",
  "dns": {
    "nameservers": ["$DNSClusterIP"],
    "search": $DNSSuffixSearchList
  }
}
"@

  Set-Content -Value $CNIConfig -Path $CNIConfigFile -Encoding ASCII
}

function Register-KubernetesServices {
<#
.SYNOPSIS
Registers kubelet and kube-proxy services
.PARAMETER KubeletServiceName
Kubelet service name
.PARAMETER KubeProxyServiceName
Kube-proxy service name
#>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)]
    [string]$KubeletServiceName,
    [Parameter(Mandatory=$true)]
    [string]$KubeProxyServiceName
  )

  [string]$PodInfraContainerImage = Get-EKSPauseImage
  [string]$InternalIP = Get-EC2MetaData 'latest/meta-data/local-ipv4'
  [string]$HostName = Get-EC2MetaData 'latest/meta-data/local-hostname'

  [string]$KubeletArgs = [string]::Join(' ', @(
     "--node-ip=$InternalIP"
  ))

  [string]$KubeletArgs = [string]::Join(' ', @(
    "--cloud-provider=aws",
    "--kubeconfig=`"$KubeConfigFile`"",
    "--hostname-override=$HostName",
    "--v=1",
    "--pod-infra-container-image=`"$PodInfraContainerImage`"",
    "--resolv-conf=`"`"",
    "--allow-privileged=true",
    "--enable-debugging-handlers",
    "--image-pull-progress-deadline=20m",
    "--cgroups-per-qos=false",
    "--enforce-node-allocatable=`"`"",
    "--network-plugin=cni",
    "--cni-bin-dir=`"$CNIBinDir`"",
    "--cni-conf-dir=`"$CNIConfigDir`"",
    "--config=`"$KubeletConfigFile`"",
    "--logtostderr=true",
    $KubeletArgs,
    $KubeletExtraArgs
  ))

  New-Service -Name $KubeletServiceName -BinaryPathName "`"$ServiceHostExe`" $KubeletServiceName `"$Kubelet`" $KubeletArgs"

  [string]$EniMACAddress = Get-EC2MetaData 'latest/meta-data/mac'
  [string]$ClusterCIDR = Get-EC2MetaData "latest/meta-data/network/interfaces/macs/$EniMACAddress/vpc-ipv4-cidr-block"
  [string]$KubeProxyArgs = [string]::Join(' ', @(
    "--kubeconfig=`"$KubeConfigFile`"",
    "--v=1",
    "--proxy-mode=kernelspace",
    "--hostname-override=$HostName",
    "--cluster-cidr=`"$ClusterCIDR`"",
    "--resource-container=`"`"",
    "--logtostderr=true"
  ))

  New-Service -Name $KubeProxyServiceName -BinaryPathName "`"$ServiceHostExe`" $KubeProxyServiceName `"$Kubeproxy`" $KubeProxyArgs"
}

function Generate-ResolvConf {
<#
.SYNOPSIS
Generates resolv.conf file in c:/etc/resolv.conf to be consumed by CoreDns POD
#>
  [System.IO.DirectoryInfo]$ResolvDir = "c:\etc"
  [string]$ResolvFile = "${ResolvDir}\resolv.conf"

  # Creating resolv dir, if it doesn't exist
  if(-not $ResolvDir.Exists) {
    Write-Information "Creating resolv directory  : $ResolvDir"
    $ResolvDir.Create()
  }

  # Getting unique comma separated Dns servers from the Ipv4 network interfaces (AddressFamily 2 represents IPv4)
  [string]$Dnsservers = (Get-DnsClientServerAddress | Where-Object {$_.AddressFamily -eq "2" -and $_.ServerAddresses -ne ""} | Select  -Expandproperty ServerAddresses -unique) -join ","
  Write-Information "Unique Dns servers : $Dnsservers"

  [string]$ResolvContent = "nameserver $Dnsservers"
  Set-Content -Value $ResolvContent -Path $ResolvFile -Encoding ASCII
}

# Initialize AWS default configuration 
Write-Information 'Initializing AWS default configurations...'
Initialize-AWSDefaultConfiguration

# Initialize default values
Write-Information 'Initializing default values...'
Initialize-DefaultValues

# Generating kube configuration
Write-Information 'Creating/Updating kubeconfig...'
Update-KubeConfig

# Generating EKS cni plugin configuration
Write-Information 'Creating/Updating EKS CNI plugin config...'
Update-EKSCNIConfig

# Generating kubelet configuration file 
Write-Information 'Creating/Updating kubelet configuration file...'
Update-Kubeletconfig

# Registering kubelet and kube-proxy services
Write-Information 'Registering kublet and kube-proxy services...'
Register-KubernetesServices 'kubelet' 'kube-proxy'

# Generating resolv.conf file to be used by coredns plugin
Write-Information 'Generating resolvconf file...'
Generate-ResolvConf

# Enable and run EKS Windows Startup task
Enable-ScheduledTask -TaskName $StartupTaskName
Start-ScheduledTask -TaskName $StartupTaskName
# SIG # Begin signature block
# MIIePAYJKoZIhvcNAQcCoIIeLTCCHikCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD0fP6IwcVRnXCa
# IIXFSl4nUuB5MxZFqh4Tj2vsKB8wxqCCDJwwggXYMIIEwKADAgECAhABVznfx2xi
# Vuf0Y3KCrPFgMA0GCSqGSIb3DQEBCwUAMGwxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xKzApBgNV
# BAMTIkRpZ2lDZXJ0IEVWIENvZGUgU2lnbmluZyBDQSAoU0hBMikwHhcNMTcwNjAx
# MDAwMDAwWhcNMjAwNjA0MTIwMDAwWjCCAR0xHTAbBgNVBA8MFFByaXZhdGUgT3Jn
# YW5pemF0aW9uMRMwEQYLKwYBBAGCNzwCAQMTAlVTMRkwFwYLKwYBBAGCNzwCAQIT
# CERlbGF3YXJlMRAwDgYDVQQFEwc0MTUyOTU0MRgwFgYDVQQJEw80MTAgVGVycnkg
# QXZlIE4xDjAMBgNVBBETBTk4MTA5MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHU2VhdHRsZTEiMCAGA1UEChMZQW1hem9uIFdlYiBT
# ZXJ2aWNlcywgSW5jLjEUMBIGA1UECxMLRUMyIFdpbmRvd3MxIjAgBgNVBAMTGUFt
# YXpvbiBXZWIgU2VydmljZXMsIEluYy4wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
# ggEKAoIBAQDIcVfNSR3j5LoUqVUMtxS4NIJq/qOGQMGnTz95nmtpLOG8nv47GzUx
# zFkqnFmDxxjV9LUoMd5yZhVWyfEIMv7RsV0RhMZqJ/rutNfwt3r/4htqxDqiUHwN
# UKtqoHOw0Q2qSyKFbawCUbm/Bf3r/ya5ACbEz/abzCivvJsvQoRtflyfCemwF2Qu
# K8aw5c98Ab9xl0/ZJgd+966Bvxjf2VVKWf5pOuQKNo6ncZOU9gtgk8uV8h5yIttF
# sJP7KpN/hoXZC88EZXzjizSuLhutd7TEzBY56Lf9q0giZ+R8iiYQdenkKBGp75uv
# UqbJV+hjndohgKRZ8EnWQFVvVm2raAZTAgMBAAGjggHBMIIBvTAfBgNVHSMEGDAW
# gBSP6H7wbTJqAAUjx3CXajqQ/2vq1DAdBgNVHQ4EFgQUpJ202cGjSh7SNUwws5w6
# QmE9IYUwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMHsGA1Ud
# HwR0MHIwN6A1oDOGMWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9FVkNvZGVTaWdu
# aW5nU0hBMi1nMS5jcmwwN6A1oDOGMWh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9F
# VkNvZGVTaWduaW5nU0hBMi1nMS5jcmwwSwYDVR0gBEQwQjA3BglghkgBhv1sAwIw
# KjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzAHBgVn
# gQwBAzB+BggrBgEFBQcBAQRyMHAwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRp
# Z2ljZXJ0LmNvbTBIBggrBgEFBQcwAoY8aHR0cDovL2NhY2VydHMuZGlnaWNlcnQu
# Y29tL0RpZ2lDZXJ0RVZDb2RlU2lnbmluZ0NBLVNIQTIuY3J0MAwGA1UdEwEB/wQC
# MAAwDQYJKoZIhvcNAQELBQADggEBAATn4LxNeqlebC8j+gebBiwGYYbc8mM+5NUp
# me5SdJHXsOQptpl9jnZFboEVDltnxfHEMtebLGqX5kz7weqt5HpWatcjvMTTbZrq
# OMTVvsrNgcSjJ/VZoaWqmFsu4uHuwHXCHyqFUA5BxSqJrMjLLYNh5SE/Z8jQ2BAY
# nZhahetnz7Od2IoJzNgRqSHM/OXsZrTKsxv+o8qPqUKwhu+5HFHS+fXXvv5iZ9MO
# LcKTPZYecojbgdZCk+qCYuhyThSR3AUdlRAHHnJyMckNUitEiRNQtxXZ8Su1yBF5
# BExMdUEFAGCHyXq3zUg5g+6Ou53VYmGMJNTIDh77kp10b8usIB4wgga8MIIFpKAD
# AgECAhAD8bThXzqC8RSWeLPX2EdcMA0GCSqGSIb3DQEBCwUAMGwxCzAJBgNVBAYT
# AlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2Vy
# dC5jb20xKzApBgNVBAMTIkRpZ2lDZXJ0IEhpZ2ggQXNzdXJhbmNlIEVWIFJvb3Qg
# Q0EwHhcNMTIwNDE4MTIwMDAwWhcNMjcwNDE4MTIwMDAwWjBsMQswCQYDVQQGEwJV
# UzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQu
# Y29tMSswKQYDVQQDEyJEaWdpQ2VydCBFViBDb2RlIFNpZ25pbmcgQ0EgKFNIQTIp
# MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp1P6D7K1E/Fkz4SA/K6A
# NdG218ejLKwaLKzxhKw6NRI6kpG6V+TEyfMvqEg8t9Zu3JciulF5Ya9DLw23m7RJ
# Ma5EWD6koZanh08jfsNsZSSQVT6hyiN8xULpxHpiRZt93mN0y55jJfiEmpqtRU+u
# fR/IE8t1m8nh4Yr4CwyY9Mo+0EWqeh6lWJM2NL4rLisxWGa0MhCfnfBSoe/oPtN2
# 8kBa3PpqPRtLrXawjFzuNrqD6jCoTN7xCypYQYiuAImrA9EWgiAiduteVDgSYuHS
# cCTb7R9w0mQJgC3itp3OH/K7IfNs29izGXuKUJ/v7DYKXJq3StMIoDl5/d2/PToJ
# JQIDAQABo4IDWDCCA1QwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMC
# AYYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwfwYIKwYBBQUHAQEEczBxMCQGCCsGAQUF
# BzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wSQYIKwYBBQUHMAKGPWh0dHA6
# Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEhpZ2hBc3N1cmFuY2VFVlJv
# b3RDQS5jcnQwgY8GA1UdHwSBhzCBhDBAoD6gPIY6aHR0cDovL2NybDMuZGlnaWNl
# cnQuY29tL0RpZ2lDZXJ0SGlnaEFzc3VyYW5jZUVWUm9vdENBLmNybDBAoD6gPIY6
# aHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0SGlnaEFzc3VyYW5jZUVW
# Um9vdENBLmNybDCCAcQGA1UdIASCAbswggG3MIIBswYJYIZIAYb9bAMCMIIBpDA6
# BggrBgEFBQcCARYuaHR0cDovL3d3dy5kaWdpY2VydC5jb20vc3NsLWNwcy1yZXBv
# c2l0b3J5Lmh0bTCCAWQGCCsGAQUFBwICMIIBVh6CAVIAQQBuAHkAIAB1AHMAZQAg
# AG8AZgAgAHQAaABpAHMAIABDAGUAcgB0AGkAZgBpAGMAYQB0AGUAIABjAG8AbgBz
# AHQAaQB0AHUAdABlAHMAIABhAGMAYwBlAHAAdABhAG4AYwBlACAAbwBmACAAdABo
# AGUAIABEAGkAZwBpAEMAZQByAHQAIABDAFAALwBDAFAAUwAgAGEAbgBkACAAdABo
# AGUAIABSAGUAbAB5AGkAbgBnACAAUABhAHIAdAB5ACAAQQBnAHIAZQBlAG0AZQBu
# AHQAIAB3AGgAaQBjAGgAIABsAGkAbQBpAHQAIABsAGkAYQBiAGkAbABpAHQAeQAg
# AGEAbgBkACAAYQByAGUAIABpAG4AYwBvAHIAcABvAHIAYQB0AGUAZAAgAGgAZQBy
# AGUAaQBuACAAYgB5ACAAcgBlAGYAZQByAGUAbgBjAGUALjAdBgNVHQ4EFgQUj+h+
# 8G0yagAFI8dwl2o6kP9r6tQwHwYDVR0jBBgwFoAUsT7DaQP4v0cB1JgmGggC72Nk
# K8MwDQYJKoZIhvcNAQELBQADggEBABkzSgyBMzfbrTbJ5Mk6u7UbLnqi4vRDQhee
# v06hTeGx2+mB3Z8B8uSI1en+Cf0hwexdgNLw1sFDwv53K9v515EzzmzVshk75i7W
# yZNPiECOzeH1fvEPxllWcujrakG9HNVG1XxJymY4FcG/4JFwd4fcyY0xyQwpojPt
# jeKHzYmNPxv/1eAal4t82m37qMayOmZrewGzzdimNOwSAauVWKXEU1eoYObnAhKg
# uSNkok27fIElZCG+z+5CGEOXu6U3Bq9N/yalTWFL7EZBuGXOuHmeCJYLgYyKO4/H
# mYyjKm6YbV5hxpa3irlhLZO46w4EQ9f1/qbwYtSZaqXBwfBklIAxghD2MIIQ8gIB
# ATCBgDBsMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSswKQYDVQQDEyJEaWdpQ2VydCBFViBDb2Rl
# IFNpZ25pbmcgQ0EgKFNIQTIpAhABVznfx2xiVuf0Y3KCrPFgMA0GCWCGSAFlAwQC
# AQUAoHwwEAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcC
# AQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIE
# II5I94mCJN3gHQBj5BXDcd1m+TsN0TE449oDuNDBgHRyMA0GCSqGSIb3DQEBAQUA
# BIIBAASztkumFW76ncafEmRLRBZ75czo4EseGEMxwCZ5eOXYBHI2bsaL7RzKLsr8
# cowNWZeYPlqLdGopqDFtkLES7tKKt6FGVGRHdjl0Ta1Me7tSRHSOI6VV06P5Z2b3
# VA9GPzSzfZxPT/526WzMKVoUykyf4OwP1+Gks8AHJcYx0sul5UYE4wLNOuH8eKET
# DXWlmxsYvaiDbGBLFqK1k+UFU750z7595AAIgR1kKLQkBio6rBAa5VGOtgeNtfyw
# 0ezgHC/79sjK4DGDbEwXdEJDMeZKA7Xz+TgnAV42lOBhs4Vp88NeiGP1jQCmy4aa
# Dyg6f5Yt1iE51E7CTTvJlI9AEsehgg7IMIIOxAYKKwYBBAGCNwMDATGCDrQwgg6w
# BgkqhkiG9w0BBwKggg6hMIIOnQIBAzEPMA0GCWCGSAFlAwQCAQUAMHcGCyqGSIb3
# DQEJEAEEoGgEZjBkAgEBBglghkgBhv1sBwEwMTANBglghkgBZQMEAgEFAAQgMFCp
# s0+p5Yy8gwzrWjrjdxp2FUuY6+mhHqbp9pDTJkoCEBx5719ugrzpGGSCik7eWUkY
# DzIwMTkwOTI2MDE0NDU0WqCCC7swggaCMIIFaqADAgECAhAJwPxGyARCE7VZi68o
# T05BMA0GCSqGSIb3DQEBCwUAMHIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdp
# Q2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xMTAvBgNVBAMTKERp
# Z2lDZXJ0IFNIQTIgQXNzdXJlZCBJRCBUaW1lc3RhbXBpbmcgQ0EwHhcNMTcwMTA0
# MDAwMDAwWhcNMjgwMTE4MDAwMDAwWjBMMQswCQYDVQQGEwJVUzERMA8GA1UEChMI
# RGlnaUNlcnQxKjAoBgNVBAMTIURpZ2lDZXJ0IFNIQTIgVGltZXN0YW1wIFJlc3Bv
# bmRlcjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ6VmGo0O3MbqH78
# x74paYnHaCZGXz2NYnOHgaOhnPC3WyQ3WpLU9FnXdonk3NUn8NVmvArutCsxZ6xY
# xUqRWStFHgkB1mSzWe6NZk37I17MEA0LimfvUq6gCJDCUvf1qLVumyx7nee1Pvt4
# zTJQGL9AtUyMu1f0oE8RRWxCQrnlr9bf9Kd8CmiWD9JfKVfO+x0y//QRoRMi+xLL
# 79dT0uuXy6KsGx2dWCFRgsLC3uorPywihNBD7Ds7P0fE9lbcRTeYtGt0tVmveFdp
# yA8JAnjd2FPBmdtgxJ3qrq/gfoZKXKlYYahedIoBKGhyTqeGnbUCUodwZkjTju+B
# JMzc2GUCAwEAAaOCAzgwggM0MA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAA
# MBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMIIBvwYDVR0gBIIBtjCCAbIwggGhBglg
# hkgBhv1sBwEwggGSMCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2VydC5j
# b20vQ1BTMIIBZAYIKwYBBQUHAgIwggFWHoIBUgBBAG4AeQAgAHUAcwBlACAAbwBm
# ACAAdABoAGkAcwAgAEMAZQByAHQAaQBmAGkAYwBhAHQAZQAgAGMAbwBuAHMAdABp
# AHQAdQB0AGUAcwAgAGEAYwBjAGUAcAB0AGEAbgBjAGUAIABvAGYAIAB0AGgAZQAg
# AEQAaQBnAGkAQwBlAHIAdAAgAEMAUAAvAEMAUABTACAAYQBuAGQAIAB0AGgAZQAg
# AFIAZQBsAHkAaQBuAGcAIABQAGEAcgB0AHkAIABBAGcAcgBlAGUAbQBlAG4AdAAg
# AHcAaABpAGMAaAAgAGwAaQBtAGkAdAAgAGwAaQBhAGIAaQBsAGkAdAB5ACAAYQBu
# AGQAIABhAHIAZQAgAGkAbgBjAG8AcgBwAG8AcgBhAHQAZQBkACAAaABlAHIAZQBp
# AG4AIABiAHkAIAByAGUAZgBlAHIAZQBuAGMAZQAuMAsGCWCGSAGG/WwDFTAfBgNV
# HSMEGDAWgBT0tuEgHf4prtLkYaWyoiWyyBc1bjAdBgNVHQ4EFgQU4acySu4BISh9
# VNXyB5JutAcPPYcwcQYDVR0fBGowaDAyoDCgLoYsaHR0cDovL2NybDMuZGlnaWNl
# cnQuY29tL3NoYTItYXNzdXJlZC10cy5jcmwwMqAwoC6GLGh0dHA6Ly9jcmw0LmRp
# Z2ljZXJ0LmNvbS9zaGEyLWFzc3VyZWQtdHMuY3JsMIGFBggrBgEFBQcBAQR5MHcw
# JAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBPBggrBgEFBQcw
# AoZDaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0U0hBMkFzc3Vy
# ZWRJRFRpbWVzdGFtcGluZ0NBLmNydDANBgkqhkiG9w0BAQsFAAOCAQEAHvBBgjKu
# 7fG0NRPcUMLVl64iIp0ODq8z00z9fL9vARGnlGUiXMYiociJUmuajHNc2V4/Mt4W
# YEyLNv0xmQq9wYS3jR3viSYTBVbzR81HW62EsjivaiO1ReMeiDJGgNK3ppki/cF4
# z/WL2AyMBQnuROaA1W1wzJ9THifdKkje2pNlrW5lo5mnwkAOc8xYT49FKOW8nIjm
# KM5gXS0lXYtzLqUNW1Hamk7/UAWJKNryeLvSWHiNRKesOgCReGmJZATTXZbfKr/5
# pUwsk//mit2CrPHSs6KGmsFViVZqRz/61jOVQzWJBXhaOmnaIrgEQ9NvaDU2ehQ+
# RemYZIYPEwwmSjCCBTEwggQZoAMCAQICEAqhJdbWMht+QeQF2jaXwhUwDQYJKoZI
# hvcNAQELBQAwZTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZ
# MBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEkMCIGA1UEAxMbRGlnaUNlcnQgQXNz
# dXJlZCBJRCBSb290IENBMB4XDTE2MDEwNzEyMDAwMFoXDTMxMDEwNzEyMDAwMFow
# cjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQ
# d3d3LmRpZ2ljZXJ0LmNvbTExMC8GA1UEAxMoRGlnaUNlcnQgU0hBMiBBc3N1cmVk
# IElEIFRpbWVzdGFtcGluZyBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
# ggEBAL3QMu5LzY9/3am6gpnFOVQoV7YjSsQOB0UzURB90Pl9TWh+57ag9I2ziOSX
# v2MhkJi/E7xX08PhfgjWahQAOPcuHjvuzKb2Mln+X2U/4Jvr40ZHBhpVfgsnfsCi
# 9aDg3iI/Dv9+lfvzo7oiPhisEeTwmQNtO4V8CdPuXciaC1TjqAlxa+DPIhAPdc9x
# ck4Krd9AOly3UeGheRTGTSQjMF287DxgaqwvB8z98OpH2YhQXv1mblZhJymJhFHm
# gudGUP2UKiyn5HU+upgPhH+fMRTWrdXyZMt7HgXQhBlyF/EXBu89zdZN7wZC/aJT
# Kk+FHcQdPK/P2qwQ9d2srOlW/5MCAwEAAaOCAc4wggHKMB0GA1UdDgQWBBT0tuEg
# Hf4prtLkYaWyoiWyyBc1bjAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823I
# DzASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAK
# BggrBgEFBQcDCDB5BggrBgEFBQcBAQRtMGswJAYIKwYBBQUHMAGGGGh0dHA6Ly9v
# Y3NwLmRpZ2ljZXJ0LmNvbTBDBggrBgEFBQcwAoY3aHR0cDovL2NhY2VydHMuZGln
# aWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNydDCBgQYDVR0fBHow
# eDA6oDigNoY0aHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJl
# ZElEUm9vdENBLmNybDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0Rp
# Z2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDBQBgNVHSAESTBHMDgGCmCGSAGG/WwA
# AgQwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzAL
# BglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggEBAHGVEulRh1Zpze/d2nyqY3qz
# eM8GN0CE70uEv8rPAwL9xafDDiBCLK938ysfDCFaKrcFNB1qrpn4J6JmvwmqYN92
# pDqTD/iy0dh8GWLoXoIlHsS6HHssIeLWWywUNUMEaLLbdQLgcseY1jxk5R9IEBhf
# iThhTWJGJIdjjJFSLK8pieV4H9YLFKWA1xJHcLN11ZOFk362kmf7U2GJqPVrlsD0
# WGkNfMgBsbkodbeZY4UijGHKeZR+WfyMD+NvtQEmtmyl7odRIeRYYJu6DC0rbaLE
# frvEJStHAgh8Sa4TtuF8QkIoxhhWz0E0tmZdtnR79VYzIi8iNrJLokqV2PWmjlIx
# ggJNMIICSQIBATCBhjByMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQg
# SW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMTEwLwYDVQQDEyhEaWdpQ2Vy
# dCBTSEEyIEFzc3VyZWQgSUQgVGltZXN0YW1waW5nIENBAhAJwPxGyARCE7VZi68o
# T05BMA0GCWCGSAFlAwQCAQUAoIGYMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRAB
# BDAcBgkqhkiG9w0BCQUxDxcNMTkwOTI2MDE0NDU0WjArBgsqhkiG9w0BCRACDDEc
# MBowGDAWBBRAAZFHXJiJHeuhBK9HCRtettTLyzAvBgkqhkiG9w0BCQQxIgQg/9Qv
# JJk5suiYwV4qD4/MQvfgsuJMJL+5Qa2qn1VYT6AwDQYJKoZIhvcNAQEBBQAEggEA
# TWRXv5e6QhD6QpF2JihZycyZq8pek7wJjnXDos69VQN1RsDxXPOOPCl0pyIjDUPN
# 8Hr7+QapwYUbO513cjjeTlqK0OtSO0V2FEZUKOKeU7O+VJQAHqJL7ViUJ8i1UK/I
# JGZdihggS2pJSVu+PN2bcWq85He2tJiOYJOMGjP8upt+maALyOxtD0ySxtyaYO52
# NDcoJ+kQ93+W6PDYQJqE8LpG7PEEu3YUeyUdifth5ER45c5lxHmz90jEBn1CDOTX
# Le1WnfH+i/SnDRF7gsj5ccOuhixEAxyWs8QzoxRkomgZbEj7psNH9kTTXwwQMiOd
# FkAUtbfrjxBC/YwbnpHMdA==
# SIG # End signature block
