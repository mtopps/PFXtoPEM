<# This form was created using POSHGUI.com  a free online gui designer for PowerShell
.NAME
    Convert PFX to PEM
#>

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

$Form = New-Object system.Windows.Forms.Form
$Form.ClientSize = New-Object System.Drawing.Point(555, 305)
$Form.text = "PFX to PEM Converter"
$Form.FormBorderStyle = 'Fixed3D'
$Form.MaximizeBox = 'False'
$Form.TopMost = $true

$SelectPFX = New-Object system.Windows.Forms.Button
$SelectPFX.text = "Select PFX"
$SelectPFX.width = 92
$SelectPFX.height = 30
$SelectPFX.location = New-Object System.Drawing.Point(31, 90)
$SelectPFX.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 10)
$SelectPFX.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#9b9b9b")

$SelectPFXTextBox = New-Object system.Windows.Forms.TextBox
$SelectPFXTextBox.multiline = $false
$SelectPFXTextBox.width = 392
$SelectPFXTextBox.height = 20
$SelectPFXTextBox.location = New-Object System.Drawing.Point(135, 96)
$SelectPFXTextBox.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 10)

$LastResultLabel = New-Object system.Windows.Forms.Label
$LastResultLabel.AutoSize = $false
$LastResultLabel.width = 501
$LastResultLabel.height = 96
$LastResultLabel.location = New-Object System.Drawing.Point(27, 161)
$LastResultLabel.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 10)
$LastResultLabel.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#b8e986")

$ConvertPFX = New-Object system.Windows.Forms.Button
$ConvertPFX.text = "Convert"
$ConvertPFX.width = 498
$ConvertPFX.height = 30
$ConvertPFX.location = New-Object System.Drawing.Point(29, 267)
$ConvertPFX.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 10)
$ConvertPFX.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#9b9b9b")

$PasswordTextBox1 = New-Object system.Windows.Forms.MaskedTextBox
$PasswordTextBox1.multiline = $false
$PasswordTextBox1.PasswordChar = '*'
$PasswordTextBox1.width = 188
$PasswordTextBox1.height = 20
$PasswordTextBox1.location = New-Object System.Drawing.Point(135, 44)
$PasswordTextBox1.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 10)

$Label1 = New-Object system.Windows.Forms.Label
$Label1.text = "Password"
$Label1.AutoSize = $true
$Label1.width = 25
$Label1.height = 10
$Label1.location = New-Object System.Drawing.Point(41, 49)
$Label1.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 10)

$Label2 = New-Object system.Windows.Forms.Label
$Label2.text = "Last Result"
$Label2.AutoSize = $true
$Label2.width = 25
$Label2.height = 10
$Label2.location = New-Object System.Drawing.Point(243, 132)
$Label2.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 13)

$WinForm1 = New-Object system.Windows.Forms.Form
$WinForm1.ClientSize = New-Object System.Drawing.Point(555, 305)
$WinForm1.text = "PFX to PEM Converter"
$WinForm1.TopMost = $true

$Form.controls.AddRange(@($SelectPFX, $SelectPFXTextBox, $LastResultLabel, $ConvertPFX, $PasswordTextBox1, $Label1, $Label2))

$SelectPFX.Add_Click( { Select-PFX })
$ConvertPFX.Add_Click( { ConvertPFX })


Set-Location $PSScriptRoot
$currentpath = Get-Location
#set PATH for openssl
$env:path = $env:path + ";$currentpath"
$env:OPENSSL_CONF = "$currentpath\openssl.cnf"
#check if openssl is installed
if (!(Get-Command -Name openssl -ErrorAction SilentlyContinue))
{ 
    Add-Type -AssemblyName PresentationCore, PresentationFramework
    [System.Windows.MessageBox]::Show('"openssl is not installed.. `nPlease install openssl"')
    Pause
    Exit
}



function Test-IsAdmin
{
    try
    {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal -ArgumentList $identity
        return $principal.IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator )
    }
    catch
    {
        throw "Failed to determine if the current user has elevated privileges. The error was: '{0}'." -f $_
    }
}

function Select-PFX
{
    $SelectPFXTextBox.Text = Get-FileName -initialDirectory $SelectPFXTextBox.Text
}


function Get-FileName($initialDirectory)
{   
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") |
        Out-Null

    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.initialDirectory = $initialDirectory
    $OpenFileDialog.filter = "PFX (*.PFX)| *.PFX"
    $OpenFileDialog.ShowDialog() | Out-Null
    $OpenFileDialog.filename
} 

function ConvertPFX
{
    $pfx_cert = $SelectPFXTextBox.Text
    $dir = Split-Path $SelectPFXTextBox.Text
    $cert = "$dir\cert.pem"
    $encryptedkey = "$dir\encrypted.key"
    $cacert = "$dir\cacert.pem"
    $unencryptedkey = "$dir\unencrypted.key"
    $fullchain = "$dir\fullchain.pem"
    
    if ($PasswordTextBox1.text -ne '' -and $pfx_cert.EndsWith(".pfx") -eq $true)
    {
        $pass = $PasswordTextBox1.text
        $LastResultLabel.text = "Extracting the certificate from $pfx_cert"
        openssl pkcs12 -in $pfx_cert -clcerts -nokeys -out $cert -passin pass:$pass 
        $LastResultLabel.text = "Extracting the key from $pfx_cert "
        openssl pkcs12 -in $pfx_cert -nocerts -out $encryptedkey -passin pass:$pass -passout pass:$pass 
        $LastResultLabel.text = "Extracting the CaChain from $pfx_cert"
        openssl pkcs12 -in $pfx_cert -nodes -nokeys -cacerts -out $cacert -passin pass:$pass 
        $LastResultLabel.text = "Wrting an unencrypted key file to $unencryptedkey"  
        openssl rsa -in $encryptedkey -out $unencryptedkey -passin pass:$pass 
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
        $LastResultLabel.text = "All certficates have been successfully exported. `nAll files have been moved to $dest `nPlease delete $dest\$pfx_remove after you're done with it"
        explorer $dest 
    }
    else
    {
        Add-Type -AssemblyName PresentationCore, PresentationFramework
        [System.Windows.MessageBox]::Show('You did not enter a password. Please Enter a Password')

    }
}



#Check if Admin Rights
if (-not(Test-IsAdmin))
{
    $LastResultLabel.text = "Please Rerun this Powershell Script with Admin Rights"
}
if (Test-IsAdmin)
{
    $LastResultLabel.text = "Running as Admin!"
}




[void]$Form.ShowDialog()