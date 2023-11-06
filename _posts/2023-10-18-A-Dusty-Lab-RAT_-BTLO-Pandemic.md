---
title: "Dusty Lab RAT -> BTLO: Pandemic"
layout: post
---

This writeup will walk through a dynamic malware analysis lab on [blueteamlabs](https://blueteamlabs.online/) named Pandemic. The scenario for this lab is that we have a malware sample from some sort of phishing campaign and are tasked with analyzing it to figure out its functionality and grab some IOCs.

**Scenario text:** *The second wave of the pandemic started. Cybercriminals also started their second wave of attacks. Here comes the new phishing technique: Alert! Alert! Alert! There are Masks to safeguard yourself from the Pandemic, but do you have a Mask on your PC??? Our OS Vendor released a new PandemicSavior Updater which will act as a Mask to safeguard yourself from the Pandemic. Immediately download the attachment and Run the Update!!! Quick !!! As a malware analyst, your IR team approached you to decide whether the attachment is safe or not. If it’s not safe, provide the IoC’s. Malware sample and the necessary toolkit is available on the Desktop*


## Initial Analysis

After dropping the sample in PE-View we can tell that the sample is most likely a <code class="language-plaintext highlighter-rouge">Delphi</code> binary, packed with <code class="language-plaintext highlighter-rouge">UPX</code>. We can tell from seeing DVCLAL (Delphi Visual Component Library Access License) in RCDATA and the compiler timestamp in the IMAGE_FILE_HEADER (the timestamp is a well-known bug in Delphi 4-2006). We see that the sample has a large resource labeled <code class="language-plaintext highlighter-rouge">CERBERUS</code> as well as an resource labeled <code class="language-plaintext highlighter-rouge">A02</code>. <code class="language-plaintext highlighter-rouge">answer 2: 19/06/1992, UPX</code>.

![Alt text](../assets/img/pe_view.png)

Making a copy of the sample in the directory and then dragging the copy to the desktop results in Defender quarantining the sample, labeling it as <code class="language-plaintext highlighter-rouge">'Worm:Win32/Rebhip.V'</code>. We can grab a hash of the sample with <code class="language-plaintext highlighter-rouge">Get-FileHash pandemichero.exe</code> in PowerShell and then search that on <code class="language-plaintext highlighter-rouge">virustotal.com</code>. Based on the results found on VT and finding 'Cerberus' a few times in PE View, we can make a good guess that this 'Cerberus RAT' (an older sample that was active from around the 2008-2010 time period (not to be confused with the popular APK banking trojan also named Cerberus)). <code class="language-plaintext highlighter-rouge">Answer 10: Cerberus</code>.

**Sample hash: C4C83313F96E8D8C50F02249289DE652A2F757BD3012153DD26086463187C194**

If we throw the sample in Resource Hacker and take a look at the icons, we can see the text <code class="language-plaintext highlighter-rouge">answer 1: Covid Mask</code>. 

![Alt text](../assets/img/icon.png)

## Dynamic Analysis

Running strings over the sample resulted in nothing interesting, so let's go ahead and run the sample. Before doing this, we should use RegShot and run an initial snapshot of the registry, as well as open up <code class="language-plaintext highlighter-rouge">Process Explorer</code> and <code class="language-plaintext highlighter-rouge">Procmon</code>. Once the first registry snapshot runs, go ahead and execute the sample. Upon execution a message box pops up with: <code class="language-plaintext highlighter-rouge">answer 4: "Congratulations Pandemic Hero!, You took the step to protect your PC with this Mask"</code>, heck yeah!

Watching the chain of execution in Process Explorer, we can see that the sample injects into <code class="language-plaintext highlighter-rouge">Answer 9: Internet Explorer</code>, which then shell executes <code class="language-plaintext highlighter-rouge">C:\Windows\touchmeagain.bat</code>. After adjusting file explorer view settings (disable all hides, enable show), we can see that the content of the batch script is a netcat command, with the verbose flag and IP/port: <code class="language-plaintext highlighter-rouge">answer 3: 172.16.104.128, 445</code>.

![Alt text](../assets/img/proc_tree.png)

![Alt text](../assets/img/nc_batch.png)

Viewing network activity in Process Explorer, we see the Internet Explorer process attempting to make connections to <code class="language-plaintext highlighter-rouge">answer 8: box5210.bluehost.com - 162.241.224.203:5150</code> every 10 seconds or so, which we can guess would be the C&C address. Taking a look at few other details of the running Internet Explorer process and we see a few unique mutexes (<code class="language-plaintext highlighter-rouge">Covid</code> and <code class="language-plaintext highlighter-rouge">Covid_Persist</code>). The other mutant that is interesting is <code class="language-plaintext highlighter-rouge">RasPbFile</code>, which really dates this sample back at least a decade (Microsoft RAS (Remote Access Service) has to do with the 'Dial-Up Networking Monitor' property sheet and other dialog boxes for managing or dialing phone book entries).

![Alt text](../assets/img/mutants.png)

## Reviewing Log Captures

Let's now run a second snapshot of the registry with RegShot, and once that's done, compare. Noticeable in the comparison of changes made in the registry are some values created under HKEY_CURRENT_USER\Software (these appear to be encrypted or encoded). Then for boot/logon persistence ([T1547.014](https://attack.mitre.org/techniques/T1547/014/) and [T1547.001](https://attack.mitre.org/techniques/T1547/001/)) there are ASEP(AutoStart Extenion Points)/RunKeys created in the HKEY_LOCAL_MACHINE and HKEY_CURRENT_USER hives with a stub path pointing to <code class="language-plaintext highlighter-rouge">answer 6: ImportantUpdate.exe</code>. An active setup component in HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node with the GUID and stub path of the 'update' binary (ImportantUpdate.exe) is also created. <code class="language-plaintext highlighter-rouge">Answer 7: ImportantUpdate</code>. The directory at <code class="language-plaintext highlighter-rouge">C:\Program Files (x86)\MSUpdate</code> is where this copied loader is stored in a hidden state. 

*Under HKEY_CURRENT_USER\Software\CovidUpdater and HKEY_CURRENT_USER\Software\Cerberus:*

![Alt text](../assets/img/under_HKU.png)

*ASEP/Run keys under HKLM and HKCU*

![Alt text](../assets/img/runkeys.png)

*Active setup component:*

**HKLM\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components\/{T5TBB77L-4678-0MKC-421Q-14416031DYU6}\StubPath: "C:\Program Files (x86)\MSUpdate\ImportantUpdate.exe Restart"**

Looking through the Procmon log capture, we can see the server querying for some interesting files ('PleaseStop.spy' and 'plugin.dat' are queried for and not found). We can aslo see that it drops a keylog data file named <code class="language-plaintext highlighter-rouge">answer 5: footprint.dat</code> in the same MSUpdate directory as the loader copy.

![Alt text](../assets/img/nonex_files.png)

*Confirming footprint.dat is the keylog file:*

![Alt text](../assets/img/keylogger.png)

With this we have reached the end of this analysis lab! Cheers!





