if (Test-Path variable:global:psISE)
{
    Write-Host "Please do not use PowerShell ISE to run this script. `nPlease use regular powershell as admin to run it"
    Pause
    Exit 
}

if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit 
}


Set-Location $PSScriptRoot
$currentpath = Get-Location
#set PATH for openssl
$env:path = $env:path + ";$currentpath"
$env:OPENSSL_CONF = "$currentpath\openssl.cnf"
#check if openssl is installed
if (!(Get-Command -Name openssl -ErrorAction SilentlyContinue))
{ 
    Write-Host "openssl is not installed.. Please install openssl"
    Pause
    Exit
}

#check if common.ps1 exists
Set-Location $PSScriptRoot
if (!(Test-Path $PSScriptRoot\common.ps1 -PathType Leaf))
{
    Write-Debug "common.ps1 is not present in current directory. Please add the script to this directory"
    Pause
    Exit
}
else
{
    . .\common.ps1
}

$warning = "pfx file"
$counter = 0 
Do
{
    Write-Host -ForegroundColor 'Yellow' -back 'black' "Please select the PFX file to be converted > "
    Write-Host -ForeGround 'Yellow' -back 'black' $warning
    $pfx_cert = Get-FileName
    $warning = 'You did not select a valid PFX file'
    if ($counter -ge 2)
    {
        exit -1
    }
    $counter++
} While ($pfx_cert.EndsWith(".pfx") -eq $false)


#set path to write out file 
$dir = Split-Path $pfx_cert
$cert = "$dir\cert.pem"
$encryptedkey = "$dir\encrypted.key"
$cacert = "$dir\cacert.pem"
$unencryptedkey = "$dir\unencrypted.key"
$fullchain = "$dir\fullchain.pem"
$pass = Read-Host "Enter Password for the pfx file and encrypted key."
if ($pfx_cert.EndsWith(".pfx") -eq $true )
{
    Write-Host "Extracting the certificate from $pfx_cert"
    openssl pkcs12 -in $pfx_cert -clcerts -nokeys -out $cert -passin pass:$pass 
    Write-Host "Extracting the key from $pfx_cert "
    openssl pkcs12 -in $pfx_cert -nocerts -out $encryptedkey -passin pass:$pass -passout pass:$pass 
    Write-Host "Extracting the CaChain from $pfx_cert"
    openssl pkcs12 -in $pfx_cert -nodes -nokeys -cacerts -out $cacert -passin pass:$pass 
    Write-Host "Wrting an unencrypted key file to $unencryptedkey"  
    openssl rsa -in $encryptedkey -out $unencryptedkey -passin pass:$pass 

}


#clean up certificate files
Set-Content -Path $cert -Value (Get-Content -Path $cert | Select-String -Pattern 'friendlyName', 'Bag Attributes', 'subject', 'issuer', 'localKeyID' -NotMatch) 
Set-Content -Path $cacert -Value (Get-Content -Path $cacert | Select-String -Pattern 'friendlyName', 'Bag Attributes', 'subject', 'issuer', 'localKeyID' -NotMatch) 
Set-Content -Path $encryptedkey -Value (Get-Content -Path $encryptedkey | Select-String -Pattern 'friendlyName', 'Bag Attributes', 'Microsoft', 'Key Attributes', 'localKeyID', 'X509v3 Key Usage' -NotMatch) 

#create full chain to be used for nginx/IDC if needed
Get-Content $cert | Out-File $fullchain -Encoding ascii
Get-Content $cacert | Out-File $fullchain -Encoding ascii -Append 

#create new folder with the date, and move all files into it 
$newdir = "$dir\CertExport" 
New-Item -ItemType Directory -Path "$newdir\$((Get-Date).ToString('yyyy-dd-MM'))" > $null
$curdate = (Get-Date).ToString('yyyy-dd-MM')
$dest = "$newdir\$curdate"
$files = @($pfx_cert, $cert, $encryptedkey, $unencryptedkey, $cacert, $fullchain )

foreach ($loc in $files)
{
    Move-Item -Path $loc -Destination $dest
}
$pfx_remove = (Get-ChildItem $dest -Include "*.*pfx*" -Recurse | Select-Object -ExpandProperty Name)
Write-Host "All certficates have been successfully exported. `nAll files have been moved to $dest `nPlease delete $dest\$pfx_remove after you're done with it"
 & explorer.exe $dest 
Pause 