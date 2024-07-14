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

![Highlight](/assets/posts/2024-07-14-phishing-is-real/highlight.png)