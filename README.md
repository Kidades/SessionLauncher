# SessionLauncher

There is no built in way in Windows to run a program as admin inside a standard user context without triggering an UAC prompt. If you are an admin user, you can use a scheduled task with the option "Run with highest privileges" to bypass the UAC prompt, but this does not work if you are a standard user. This option does nothing, as standard users simply don't have an elevated token, and running the task as a different user will launch it in their own session and not inside your standard user session. The built-in runas utility lets you run a program as admin, but it does not run elevated. An UAC prompt will still be triggered when the program requests elevation. Also it is a security risk, since you need to expose admin creds to the standard user.

This utility is my attempt at creating such functionality. It is quite hacky but works and does not expose admin creds to the standard user. The only downside is that it needs to be running in SYSTEM context, which is easily achievable with a scheduled task running as SYSTEM. 

# Modes

The program supports 3 modes to launch an exe into the currently active session:

Run as SYSTEM - It runs an exe interactively as the SYSTEM account, with highest privileges. The app's GUI will appear in whatever is currently the active session. This method is equivalent to using "psexec -s -i". It is not the primary function of this utility but I've included it simply since that's what I started with when developing it.

Run as ADMIN using a scheduled task - Runs an exe inside the current session as the target admin user. It requires that an elevated helper process is running as that user. It takes the elevated token from that process, duplicates it and runs our target exe as elevated. This is the indended way of using this utility.

Run as ADMIN using credentials - Runs an exe as the targeted admin user, obtaining an elevated token using the credentials of that user. This is similar to what runas does, but the program runs elevated from the start. This method is included for testing purposes and should not be used actively as it exposes admin creds.

# Usage

This utility can only work when running under SYSTEM. Either as a scheduled task with highest privileges set, or through psexec.

SessionLauncher.exe <path_to_exe> [exe_args...] [/admin [/task | /creds <username> <password>]] [/debug]

Launch options:  
**/admin** - Run the target executable as an administrator user. Program will run elevated, bypassing the UAC prompt. Specify method with either /task or /creds  
**/task** - Use in conjunction with /admin. Make sure to have the helper program LauncherHelper.exe running elevated under the target admin user, preferably via a scheduled task.  
**/creds <username> <password>** - Use in conjunction with /admin. Typing in the username and password of the target admin user account.  
**/debug** - Logs the command output to the file C:\SessionLauncher.log for debugging purposes.

## Setup
Create a scheduled task as SYSTEM with "Run with highest privileges" checked. For action set it to run the utility "SessionLauncher.exe". Set it's arguments, refer to the usage and launch options above.

Example arguments:  
**"C:/Windows/notepad.exe"**                                    ;runs notepad as SYSTEM  
**"C:/Windows/notepad.exe" /admin /creds John Password123**     ;runs notepad as the admin user John  
**"C:/Windows/notepad.exe" /admin /task**                       ;runs notepad as the admin user John, without requiring John's credentials by using a helper process already running as John  

### Launcher helper task

In order to use the /task option, you need to set a process to run as your target user. Here I've included a dummy exe that remains idle indefinitely.  
Create a scheduled task that runs as your target admin user, check "Run whether user is logged on or not", "Do not store password" and "Run with highest privileges". For action, start the program LauncherHelper.exe , without any args. For trigger you can set to either run "At startup" or "At logon" of Any User or your target user.  
SessionLauncher.exe will wait up to 10 seconds for LauncherHelper.exe to show up before erroring out, so there shouldn't be any issues if it's task launches before the helper's task.

# How does it work

1. **Starts from SYSTEM in the active user session**  
   The launcher must already run as SYSTEM. It locates the active console session and, if needed, re-runs itself inside that session so any UI appears on the logged-in user’s desktop.

2. **Grabs an elevated admin token**  
   - `/task` → duplicates the primary token of a pre-elevated helper process (e.g. a scheduled task running as an admin with “Run with highest privileges”).  
   - `/creds` → logs on the specified admin account and fetches its linked elevated token.  

3. **Prepares the token for that session**  
   The token is duplicated into a primary token, its session ID is set to the active session, and the admin profile/environment are loaded so the new process behaves like a real interactive logon.

4. **Fixes desktop permissions**  
   By briefly impersonating `winlogon.exe`, the launcher updates ACLs on `winsta0` and the `default` desktop so the new admin process can actually interact with the existing user desktop.

5. **Starts the elevated process**  
   Finally, it calls `CreateProcessAsUser` with the prepared token and desktop, starting your target app as a fully elevated admin inside the active user session — without triggering a UAC prompt.
