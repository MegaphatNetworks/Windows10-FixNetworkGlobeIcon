# Windows 10 - Fix Network Globe Icon

I have been experiencing many cases with Windows 10 where the network icon looks like this:
![NetGlobe](https://user-images.githubusercontent.com/60324301/140623915-c96a3404-27ef-4b36-ae90-900422932f52.png)

The problem is, it should not. If you are using a wired Ethernet connection it should look like this:
![NetOK](https://user-images.githubusercontent.com/60324301/140624087-69a8d562-2f11-4e2a-ae01-7792d192e0c6.png)

If you are using a Wifi connection it should look like this:
![WifiOK](https://user-images.githubusercontent.com/60324301/140624080-63a3458d-fad9-42e9-9d74-ff51343efc11.png)

So the bottom line is your Windows 10 NCSI (or *Network Connectivity Status Indicator*) is broken.  This could happen because of an update, it could happen because of a registry change performed, it could happen due to a piece of software making changes to your system and it certainly will happen if you used any type of Windows 10 cleanup tool such as my [Windows 10 Exorcist v1](https://github.com/MegaphatNetworks/Windows-10-Exorcist) (and for that I am sorry but hey at least I am giving you the fix).

NCSI is a feature within the Microsoft Windows infrastructure which applications can simply ask Windows via API *"Hey, are we connected to the Internet?"* and supposedly NCSI will accurately answer Yes or No.  For example, *Spotify Desktop* as well as *Windows Update* both use NCSI and both receive inaccurate information if you have the ![NetGlobe](https://user-images.githubusercontent.com/60324301/140623915-c96a3404-27ef-4b36-ae90-900422932f52.png)

So this script is written in Windows PowerShell.  Simply right click on the .PS1 file and select `Run With PowerShell`.  It will automatically elevate itself to Administrator (privilged-level) execution to perform the required tasks.  Now once executed and elevated permissions are granted, it will ask you if you want to run in **Normal Mode** or **Aggressive Mode**.  At first I would recommend **Normal Mode** *unless* you are running this because of a Windows 10 cleanup script (such as the [Windows 10 Exorcist v1](https://github.com/MegaphatNetworks/Windows-10-Exorcist)), in which case you should run in **Aggressive mode**.

The difference between *Normal* and *Aggressive*.

## Normal Mode
If you believe you have the ![NetGlobe](https://user-images.githubusercontent.com/60324301/140623915-c96a3404-27ef-4b36-ae90-900422932f52.png) because of a bad Windows Update (totally possible), then try Normal mode.

## Aggressive Mode
If you have the ![NetGlobe](https://user-images.githubusercontent.com/60324301/140623915-c96a3404-27ef-4b36-ae90-900422932f52.png) because of an aggressive piece of code (such as the [Windows 10 Exorcist v1](https://github.com/MegaphatNetworks/Windows-10-Exorcist)), then you will most likely need to run Aggressive mode.
  
---
  
### Common Questions
- Q: Can I run Aggressive mode after trying Normal mode?  
- A: Yes and it WILL work!
---
- Q: Will this make changes to my system?  
- A: Yes however the changes that are made will actually be reverting your system back to a *stock* NCSI configuration.  Aggressive mode as well, will revert your system to a stock configuration, but it will advance further by altering additional system settings back to their stock settings.
---
- Q: Will Aggressive mode undo Windows 10 Exorcist v1 and/or other Windows 10 cleanup scripts?  
- A: To some degree, yes.  MS Telemetry and tracking will be re-enabled but I am creating a new script to help with that which does not affect NCSI.
---
- Q: Are you making money at this?  
- A: No but I would appreciate any donations for all of my time and effort.
---
- Q: Do you have a website?  
- A: You can check out [my personal site](http://www.megaphat.info)
---
- Q: Can I contact you with any questions or for a custom script?  
- A: Sure, just go to [my personal site](http://www.megaphat.info) to reach out to me.
---
