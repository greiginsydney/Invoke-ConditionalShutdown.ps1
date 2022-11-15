# Invoke-ConditionalShutdown.ps1

Windows natively won’t let you schedule a system shutdown, but there are plenty of posts on the Internet that show you how to create a Scheduled Task that will do that for you.

Having recently added a solar+battery setup to our home, I’ve been on a (belated) mission to reduce our overnight power consumption, and I’ve decided that a scheduled shutdown of my desktop PC around bedtime would be a good idea. HOWEVER I don’t want it to be completely automatic, because sometimes I might be running a process that needs to be let run. I might have a WinSCP or PowerShell session open to a Pi I’m monitoring, or I’m capturing real-time traffic from KNX’s “ETS” app, and the shutdown would be A Bad Thing. And here’s where I hit a roadblock.

“Invoke-ConditionalShutdown.ps1” is the solution.

![image](https://user-images.githubusercontent.com/11004787/201496156-f5004990-803b-4981-b292-3d09cbafa2d9.png)

Create your scheduled task as required, but instead of calling “shutdown”, call PowerShell, invoke the script, and add some attributes to define a “skip list” of processes to whitelist, or a “skip file” with the power of regular expressions to look for a list of processes and title bar text.

## Features
 
### Simple mode

Supply a comma-separated list of process names to whitelist. e.g. “Notepad++,Bounsky 2015”.

### Power-user mode

Provide a CSV file naming the process and what its title bar must say for it to be whitelisted. These values are regular expressions, where a blank entry is a wildcard “$true”.

### Hibernate

All the power, but just hibernate instead of shutting down. (The script will abort and report an error if Hibernate is disallowed for your machine or o/s).

### Shutdown timer

Windows’ shutdown command has a “-t nn” attribute, and I’ve catered for that here too, with a default 20s delay for some in-built “OMG NOOOO” protection. (“shutdown -a” is your “undo” command here.)

### Reopen previously-running apps

If enabled and invoked, when the machine next boots, all the previously-running apps will reopen. See “ARSO” in the blog post linked below.

### Validate the RegEx in the SkipFile

Not sure if your RegEx is up to scratch? Don’t worry, neither is mine. Run the script with the “-ValidateSkipFile” switch and it will tell you which of your RegEx rules are no good. Rinse and repeat until it’s all valid, then proceed to “TestMode”.

### TestMode

Test your settings are correct without risking an unexpected shutdown/hibernate event. The script will drop a message to the screen telling you if it would have shutdown or not, and what criteria triggered the ‘skip’. (Run -ValidateSkipFile first if you’re using the SkipFile).

### Verbose

Add the -verbose switch to show all output on screen.

### Code Signed

With thanks to DigiCert, the released version of the script has been signed, so it'll run in environments where a strict security policy is enforced.

<hr>

[My blog](https://greiginsydney.com/invoke-conditionalshutdown-ps1) has the full documentation, including setup and troubleshooting steps.

&nbsp;<br>

\- Greig.
