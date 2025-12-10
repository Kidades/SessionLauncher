using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;

class SessionLauncher
{
    
    static readonly string LogPath = @"C:\SessionLauncher.log";
    private static bool debug = false;

    static void Log(string msg)
    {
        try 
        { 
            string logLine = $"[{DateTime.Now:HH:mm:ss.fff}] {msg}";
            Console.WriteLine(logLine);
            if(debug) System.IO.File.AppendAllText(LogPath, logLine + Environment.NewLine);  //Uncomment to log to file
        }
        catch { }
    }

    static void printUsage()
    {
        string exeName = Path.GetFileName(Environment.GetCommandLineArgs()[0]);
            
        if (!WindowsIdentity.GetCurrent().IsSystem)
        {
            Console.WriteLine("ERROR: You are NOT running as SYSTEM. This utility can only work when running under SYSTEM. Either as a scheduled task with highest privileges set, or through psexec.");
            Console.WriteLine();
            Console.WriteLine();
        }

        Console.WriteLine($"Usage:");
        Console.WriteLine($"  {exeName} <path_to_exe> [exe_args...] [/admin [/task | /creds <username> <password>]] [/debug]");
        Console.WriteLine();
        Console.WriteLine("Runs the target exe as the SYSTEM user and injects it into the currently active session.");
        Console.WriteLine();
        Console.WriteLine("Launch options:");
        Console.WriteLine("/admin - Run the target executable as an administrator user instead of system. Program will run elevated, bypassing the UAC prompt. Specify method with either /task or /creds");
        Console.WriteLine("/task - Use in conjunction with /admin. Make sure to have the helper program LauncherHelper.exe running elevated under the target admin user, preferably via a scheduled task.");
        Console.WriteLine("/creds <username> <password> - Use in conjunction with /admin. Typing in the username and password of the target admin user account.");
        Console.WriteLine(@"/debug - Enables logging to the file C:\SessionLauncher.log");
        Console.WriteLine();
        Console.WriteLine("This utility MUST be running under the SYSTEM user, regardless of which method of injection is used.");
        Console.WriteLine();   
        Console.WriteLine("Examples:");
        Console.WriteLine($"  {exeName} \"C:\\Tools\\MyApp.exe\"");
        Console.WriteLine($"  {exeName} \"C:\\Tools\\MyApp.exe\" -foo bar");
        Console.WriteLine($"  {exeName} \"C:\\Tools\\MyApp.exe\" -foo bar /admin /task");
        Console.WriteLine($"  {exeName} \"C:\\Tools\\MyApp.exe\" -foo bar /admin /creds John MyPass123");
    }
    
    
    static void Main(string[] args)
    {
        uint activeSessionT = WTSGetActiveConsoleSessionId();
        int currentSessionT = Process.GetCurrentProcess().SessionId;
        Log("Current session: " + currentSessionT + " Active session: " + activeSessionT + " Logged on:" + HasLoggedOnUser(activeSessionT));
        
        
        if (args.Length == 0 || args[0] == "/?" || args[0] == "-h" || args[0] == "--help" || !WindowsIdentity.GetCurrent().IsSystem)
        {
            printUsage();
            return;
        }
        
        try
        {
            
            string exePath = args[0];

            bool runAsAdmin = false;
            bool useCreds = false;
            string credUser = null;
            string credPass = null;

            var targetArgs = new System.Collections.Generic.List<string>();

            // Parse args[1..] into launcher flags vs target args
            for (int i = 1; i < args.Length; i++)
            {
                string a = args[i];

                if (string.Equals(a, "/admin", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(a, "-admin", StringComparison.OrdinalIgnoreCase))
                {
                    runAsAdmin = true;
                    // don't add to targetArgs
                }
                else if (string.Equals(a, "/task", StringComparison.OrdinalIgnoreCase))
                {
                    // Admin via scheduled-task token host
                    useCreds = false;
                }
                else if (string.Equals(a, "/debug", StringComparison.OrdinalIgnoreCase))
                {
                    debug = true;
                }
                else if (string.Equals(a, "/creds", StringComparison.OrdinalIgnoreCase))
                {
                    // Admin via explicit credentials: /creds username password
                    useCreds = true;

                    if (i + 2 >= args.Length)
                    {
                        Log("Missing username/password for /creds.");
                        return;
                    }

                    credUser = args[++i];   // username
                    credPass = args[++i];   // password
                }
                else
                {
                    // Any non-launcher-flag goes to target exe
                    targetArgs.Add(a);
                }
            }

            string cmdLine = "\"" + exePath + "\"" +
                             (targetArgs.Count > 0 ? " " + string.Join(" ", targetArgs) : "");

            IntPtr sysToken = GetSystemToken();
            if (sysToken == IntPtr.Zero) return;

            if (runAsAdmin)
            {
                
                uint activeSession = WTSGetActiveConsoleSessionId();
                if (!HasLoggedOnUser(activeSession))
                {
                    Log("No active session found. Aborting launch as user.");
                    return;
                }
                
                int currentSession = Process.GetCurrentProcess().SessionId;
                if (currentSession != activeSession)
                {
                    Log("We are not running inside the currently active session. Current session:" + currentSession + " Active session: " + activeSession +  " Relaunching the launcher interactively...");
                    LaunchSystem(sysToken, Environment.CommandLine);
                    return;
                }
                LaunchElevated(cmdLine, useCreds, credUser, credPass);
            }
            else
                LaunchSystem(sysToken, cmdLine);

            Log("Done.");
        }
        catch (Exception ex)
        {
            Log("Unhandled exception: " + ex);
        }
}


    static IntPtr GetSystemToken()
    {
        IntPtr sysToken = IntPtr.Zero;
        OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, out sysToken);
        return sysToken;
    }

    // ======================================================================================================
    //                           THE ELEVATED LAUNCHER
    // ======================================================================================================

    static void LaunchElevated(string cmdLine, bool useCreds = false, string credUser = null, string credPass = null, string credDomain = ".")
    {
        IntPtr initialToken = IntPtr.Zero;
        IntPtr elevatedToken = IntPtr.Zero;
        IntPtr primaryToken = IntPtr.Zero;
        IntPtr env = IntPtr.Zero;
        IntPtr winlogonToken = IntPtr.Zero;

        try
        {
            uint sessionId = WTSGetActiveConsoleSessionId();
            if (sessionId == 0xFFFFFFFF) throw new Exception("No active session found.");
            Log($"Target Session: {sessionId}");

      //  METHOD 1 - with admin credentials and no scheduled task
      if (useCreds)
      {
          // 1. Log on
          if (string.IsNullOrEmpty(credUser) || string.IsNullOrEmpty(credPass))
              throw new ArgumentException("Username/password required when /creds is used.");
          
          string user = credUser;
          string domain = credDomain; // or parse from user if it contains '\'

          if (!LogonUser(user, domain, credPass,
                  LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, out initialToken))
              throw new Win32Exception(Marshal.GetLastWin32Error(), "LogonUser failed");

          // 2. Get Linked Token
          elevatedToken = GetLinkedToken(initialToken);
          if (elevatedToken == IntPtr.Zero) elevatedToken = initialToken;
      }
      else //METHOD 2 - token theft from existing process running as admin and elevated
      {
          // 1. Get token from the scheduled-task dummy process (already elevated)

          Process host = null;
          Log($"Finding helper process: LauncherHelper.exe");
          for (int i = 0; i < 10; i++)
          {
              host = Process.GetProcessesByName("LauncherHelper").FirstOrDefault();
              if (host == null)
              {
                  Thread.Sleep(1000);
                  continue;
              }

              break;
              
          }

          if (host == null) 
              throw new Exception("Admin token host process not found.");
          

          IntPtr hProc = OpenProcess(PROCESS_QUERY_INFORMATION, false, host.Id);
          if (hProc == IntPtr.Zero)
              throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcess failed");

          if (!OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY, out initialToken))
              throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcessToken failed");

          CloseHandle(hProc); // we are done with the process handle

          // 2. The host process is already running 'with highest privileges', so its primary token is already elevated – no linked token needed.
          elevatedToken = initialToken;
          
          //Get the username from the token so we know whose profile to load
          using (var id = new WindowsIdentity(initialToken))
          {
              string full = id.Name;
              int slash = full.IndexOf('\\');
              credUser = (slash >= 0) ? full.Substring(slash + 1) : full;
          }
      }

      // 3. Duplicate the token to use with our new process
            SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES { nLength = (uint)Marshal.SizeOf<SECURITY_ATTRIBUTES>() };
            if (!DuplicateTokenEx(elevatedToken, MAXIMUM_ALLOWED, ref sa,
                SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                TOKEN_TYPE.TokenPrimary, out primaryToken))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "DuplicateTokenEx failed");

            // 4. Load Profile
            PROFILEINFO profileInfo = new PROFILEINFO();
            profileInfo.dwSize = Marshal.SizeOf(profileInfo);
            profileInfo.lpUserName = credUser;
            profileInfo.dwFlags = 0;
            LoadUserProfile(primaryToken, ref profileInfo); 

            // 5. GET SIDs
            string userSid = GetSidFromToken(primaryToken);
            string logonSid = GetLogonSidFromGroups(primaryToken); 

            Log($"\n=== PERMISSION PATCH DATA ===");
            Log($"User SID:  {userSid}");
            Log($"Logon SID: {logonSid ?? "NULL"}");

            // 6. PATCH PERMISSIONS (With OICI Inheritance)
            winlogonToken = GetWinlogonToken(sessionId);
            if (winlogonToken != IntPtr.Zero)
            {
                if (ImpersonateLoggedOnUser(winlogonToken))
                {
                    try
                    {
                        // 0x37F = WINSTA_ALL, 0x1FF = DESKTOP_ALL
                        // We use 'OICI' (Object Inherit, Container Inherit)
                        SafeAddSidsViaSddl("winsta0", userSid, logonSid, "0x37F", true);
                        SafeAddSidsViaSddl("default", userSid, logonSid, "0x1FF", false);
                    }
                    catch(Exception ex) { Log($"Patch Failed: {ex.Message}"); }
                    finally { RevertToSelf(); }
                }
            }
            else
            {
                Log("ERROR: Could not get Winlogon token. Patching aborted.");
            }

            // 7. Inject our process into currently active session
            if (!SetTokenInformation(primaryToken, TOKEN_INFORMATION_CLASS.TokenSessionId, ref sessionId, (uint)Marshal.SizeOf<uint>()))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "SetTokenSessionId failed");

            CreateEnvironmentBlock(out env, primaryToken, false);
            STARTUPINFO si = new STARTUPINFO { cb = (uint)Marshal.SizeOf<STARTUPINFO>(), lpDesktop = @"winsta0\default" };
            PROCESS_INFORMATION pi;

            if (!CreateProcessAsUser(primaryToken, null, cmdLine, IntPtr.Zero, IntPtr.Zero, false, 
                CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE, env, null, ref si, out pi))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateProcessAsUser failed");

            Log($"Launched ELEVATED. PID={pi.dwProcessId}");
            
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
        finally
        {
            if (env != IntPtr.Zero) DestroyEnvironmentBlock(env);
            if (primaryToken != IntPtr.Zero) CloseHandle(primaryToken);
            if (elevatedToken != IntPtr.Zero && elevatedToken != initialToken) CloseHandle(elevatedToken);
            if (initialToken != IntPtr.Zero) CloseHandle(initialToken);
            if (winlogonToken != IntPtr.Zero) CloseHandle(winlogonToken);
        }
    }

    // =======================================================================
    //                       ROBUST SID RETRIEVAL
    // =======================================================================

    static string GetSidFromToken(IntPtr hToken)
    {
        try { using (var identity = new WindowsIdentity(hToken)) { return identity.User.Value; } }
        catch { return null; }
    }

    static string GetLogonSidFromGroups(IntPtr hToken)
    {
        uint tokenInfoLen = 0;
        GetTokenInformation(hToken, (TOKEN_INFORMATION_CLASS)2, IntPtr.Zero, 0, out tokenInfoLen);
        if (tokenInfoLen == 0) return null;

        IntPtr pData = Marshal.AllocHGlobal((int)tokenInfoLen);
        try
        {
            if (!GetTokenInformation(hToken, (TOKEN_INFORMATION_CLASS)2, pData, tokenInfoLen, out tokenInfoLen)) return null;
            int groupCount = Marshal.ReadInt32(pData);
            long offset = IntPtr.Size; 
            IntPtr pCurrent = (IntPtr)((long)pData + offset);
            const uint SE_GROUP_LOGON_ID = 0xC0000000;

            for (int i = 0; i < groupCount; i++)
            {
                SID_AND_ATTRIBUTES sa = Marshal.PtrToStructure<SID_AND_ATTRIBUTES>(pCurrent);
                if ((sa.Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID)
                {
                    IntPtr pStringSid = IntPtr.Zero;
                    if (ConvertSidToStringSid(sa.Sid, out pStringSid))
                    {
                        string sid = Marshal.PtrToStringUni(pStringSid);
                        LocalFree(pStringSid);
                        return sid;
                    }
                }
                pCurrent = (IntPtr)((long)pCurrent + Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES)));
            }
        }
        finally { Marshal.FreeHGlobal(pData); }
        return null;
    }

    // =======================================================================
    //                           SDDL PATCHING 
    // =======================================================================

    static void SafeAddSidsViaSddl(string objectName, string userSid, string logonSid, string accessMask, bool isWinsta)
    {
        Log($"---> Patching {objectName}...");
        IntPtr handle = IntPtr.Zero;
        if (isWinsta)
            handle = OpenWindowStation(objectName, false, 0x40000 | 0x00020000); 
        else
            handle = OpenDesktop(objectName, 0, false, 0x40000 | 0x00020000);

        if (handle == IntPtr.Zero) { Log("Failed to open object."); return; }

        try
        {
            IntPtr pSd = IntPtr.Zero;
            IntPtr pSddl = IntPtr.Zero;
            IntPtr pNewSd = IntPtr.Zero;

            try
            {
                uint res = GetSecurityInfo(handle, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION,
                    out IntPtr _, out IntPtr _, out IntPtr _, out IntPtr _, out pSd);
                if (res != 0) throw new Exception($"GetSecurityInfo failed {res}");

                if (!ConvertSecurityDescriptorToStringSecurityDescriptor(pSd, SDDL_REVISION_1, 
                    DACL_SECURITY_INFORMATION, out pSddl, out int _))
                    throw new Exception($"ToSDDL failed {Marshal.GetLastWin32Error()}");
                
                string sddl = Marshal.PtrToStringUni(pSddl);
          //    Log($"[BEFORE] {sddl}");

                StringBuilder sb = new StringBuilder(sddl);
                bool changed = false;

                // Added 'OICI' (Object Inherit, Container Inherit) to all ACEs
                
                // 1. User
                if (!sddl.Contains(userSid)) 
                {
                    sb.Append($"(A;OICI;{accessMask};;;{userSid})");
                    changed = true;
                    Log("Added User ACE (Inheritable).");
                }

                // 2. Logon SID
                if (!string.IsNullOrEmpty(logonSid) && !sddl.Contains(logonSid)) 
                {
                    sb.Append($"(A;OICI;{accessMask};;;{logonSid})");
                    changed = true;
                    Log("Added Logon ACE (Inheritable).");
                }

                // 3. Interactive (Backup for DWM)
                if (!sddl.Contains("S-1-5-4"))
                {
                    sb.Append($"(A;OICI;{accessMask};;;S-1-5-4)");
                    changed = true;
                    Log("Added Interactive ACE (Inheritable).");
                }

                /* //4. Everyone (Fail-safe diagnostic)
                if (!sddl.Contains("S-1-1-0"))
                {
                    sb.Append($"(A;OICI;{accessMask};;;S-1-1-0)");
                    changed = true;
                    Log("Added Everyone ACE (Inheritable).");
                } */

                if (!changed) { Log("No changes needed."); return; }

                string newSddl = sb.ToString();
          //    Log($"[AFTER]  {newSddl}");

                if (!ConvertStringSecurityDescriptorToSecurityDescriptor(newSddl, SDDL_REVISION_1, 
                    out pNewSd, out int _)) 
                    throw new Exception($"FromSDDL failed {Marshal.GetLastWin32Error()}");

                IntPtr pNewDacl;
                if (!GetSecurityDescriptorDacl(pNewSd, out _, out pNewDacl, out _))
                    throw new Exception($"GetDacl failed {Marshal.GetLastWin32Error()}");

                res = SetSecurityInfo(handle, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION,
                    IntPtr.Zero, IntPtr.Zero, pNewDacl, IntPtr.Zero);

                Log(res == 0 ? "Patch Applied Successfully." : $"SetSecurityInfo failed {res}");
            }
            finally
            {
                if (pSd != IntPtr.Zero) LocalFree(pSd);
                if (pSddl != IntPtr.Zero) LocalFree(pSddl);
                if (pNewSd != IntPtr.Zero) LocalFree(pNewSd);
            }
        }
        finally
        {
            if (isWinsta) CloseWindowStation(handle);
            else CloseDesktop(handle);
        }
    }

    // =======================================================================
    //                         GENERAL HELPERS
    // =======================================================================
    
    static IntPtr GetWinlogonToken(uint sessionId)
    {
        var proc = Process.GetProcessesByName("winlogon").FirstOrDefault(p => (uint)p.SessionId == sessionId);
        if (proc == null) return IntPtr.Zero;
        IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, false, proc.Id);
        if (hProcess == IntPtr.Zero) return IntPtr.Zero;
        try
        {
            IntPtr hToken = IntPtr.Zero;
            if (OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE, out hToken)) return hToken;
        }
        finally { CloseHandle(hProcess); }
        return IntPtr.Zero;
    }

    static void LaunchSystem(IntPtr sysToken, string cmdLine)
    {
        IntPtr primaryToken = IntPtr.Zero;
        IntPtr env = IntPtr.Zero;
        try
        {
            SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES { nLength = (uint)Marshal.SizeOf<SECURITY_ATTRIBUTES>() };
            DuplicateTokenEx(sysToken, MAXIMUM_ALLOWED, ref sa, SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, TOKEN_TYPE.TokenPrimary, out primaryToken);
            uint sessionId = WTSGetActiveConsoleSessionId();
            SetTokenInformation(primaryToken, TOKEN_INFORMATION_CLASS.TokenSessionId, ref sessionId, (uint)Marshal.SizeOf<uint>());
            CreateEnvironmentBlock(out env, primaryToken, false);
            STARTUPINFO si = new STARTUPINFO { cb = (uint)Marshal.SizeOf<STARTUPINFO>(), lpDesktop = @"winsta0\default" };
            PROCESS_INFORMATION pi;
            CreateProcessAsUser(primaryToken, null, cmdLine, IntPtr.Zero, IntPtr.Zero, false, CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE, env, null, ref si, out pi);
            Log($"Launched as SYSTEM. PID={pi.dwProcessId}");
            CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        }
        finally { if (env != IntPtr.Zero) DestroyEnvironmentBlock(env); if (primaryToken != IntPtr.Zero) CloseHandle(primaryToken); }
    }
    
    static IntPtr GetLinkedToken(IntPtr hToken)
    {
        uint tokenLinkedToken = 19; 
        uint returnLen;
        IntPtr outBuffer = Marshal.AllocHGlobal(IntPtr.Size);
        try
        {
            if (GetTokenInformation(hToken, (TOKEN_INFORMATION_CLASS)tokenLinkedToken, outBuffer, (uint)IntPtr.Size, out returnLen))
                return Marshal.ReadIntPtr(outBuffer);
        }
        finally { Marshal.FreeHGlobal(outBuffer); }
        return IntPtr.Zero;
    }
    
    static bool HasLoggedOnUser(uint sessionId)
    {
        if (sessionId == 0xFFFFFFFF)
            return false;

        IntPtr buffer;
        int bytes;
        if (!WTSQuerySessionInformation(IntPtr.Zero, (int)sessionId, WTS_INFO_CLASS.WTSUserName,
                out buffer, out bytes))
            return false;

        try
        {
            string user = Marshal.PtrToStringUni(buffer);
            return !string.IsNullOrEmpty(user);
        }
        finally
        {
            WTSFreeMemory(buffer);
        }
    }

    // =======================================================================
    //                               P/INVOKES
    // =======================================================================

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool ConvertSecurityDescriptorToStringSecurityDescriptor(IntPtr SecurityDescriptor, int RequestedStringSDRevision, int SecurityInformation, out IntPtr StringSecurityDescriptor, out int StringSecurityDescriptorLen);
    
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string StringSecurityDescriptor, int StringSDRevision, out IntPtr SecurityDescriptor, out int SecurityDescriptorSize);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    static extern bool ConvertSidToStringSid(IntPtr Sid, out IntPtr StringSid);

    [StructLayout(LayoutKind.Sequential)]
    public struct SID_AND_ATTRIBUTES
    {
        public IntPtr Sid;
        public uint Attributes;
    }

    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool ImpersonateLoggedOnUser(IntPtr hToken);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool RevertToSelf();
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, ref SECURITY_ATTRIBUTES lpTokenAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, TOKEN_TYPE TokenType, out IntPtr phNewToken);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool SetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, ref uint TokenInformation, uint TokenInformationLength);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool SetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool GetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);
    [DllImport("userenv.dll", SetLastError = true)] static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);
    [DllImport("userenv.dll", SetLastError = true)] static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool CreateProcessAsUser(IntPtr hToken, string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool CloseHandle(IntPtr hObject);
    [DllImport("kernel32.dll")] static extern uint WTSGetActiveConsoleSessionId();
    [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Auto)] static extern bool LoadUserProfile(IntPtr hToken, ref PROFILEINFO lpProfileInfo);
    [DllImport("user32.dll", SetLastError = true)] static extern IntPtr OpenWindowStation(string lpszWinSta, bool fInherit, uint dwDesiredAccess);
    [DllImport("user32.dll", SetLastError = true)] static extern bool CloseWindowStation(IntPtr hWinSta);
    [DllImport("advapi32.dll", SetLastError = true)] static extern uint GetSecurityInfo(IntPtr handle, int ObjectType, int SecurityInfo, out IntPtr ppsidOwner, out IntPtr ppsidGroup, out IntPtr ppDacl, out IntPtr ppSacl, out IntPtr ppSecurityDescriptor);
    [DllImport("advapi32.dll", SetLastError = true)] static extern uint SetSecurityInfo(IntPtr handle, int ObjectType, int SecurityInfo, IntPtr psidOwner, IntPtr psidGroup, IntPtr pDacl, IntPtr pSacl);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool GetSecurityDescriptorDacl(IntPtr pSecurityDescriptor, out bool lpbDaclPresent, out IntPtr pDacl, out bool lpbDaclDefaulted);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr hMem);
    [DllImport("user32.dll", SetLastError = true)] static extern bool CloseDesktop(IntPtr hDesktop);
    [DllImport("user32.dll", SetLastError = true)] static extern IntPtr OpenDesktop(string lpszDesktop, uint dwFlags, bool fInherit, uint dwDesiredAccess);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool LogonUser(string lpszUsername, string lpszDomain, string lpszPassword, int dwLogonType, int dwLogonProvider, out IntPtr phToken);
    
    [DllImport("Wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool WTSQuerySessionInformation(IntPtr hServer, int SessionId, WTS_INFO_CLASS WTSInfoClass, out IntPtr ppBuffer, out int pBytesReturned);

    [DllImport("Wtsapi32.dll")] static extern void WTSFreeMemory(IntPtr pMemory);

    enum WTS_INFO_CLASS { WTSUserName = 5, }

    const int LOGON32_LOGON_INTERACTIVE = 2; const int LOGON32_PROVIDER_DEFAULT = 0; const uint TOKEN_ALL_ACCESS = 0xF01FF; const uint MAXIMUM_ALLOWED = 0x02000000; const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400; const uint CREATE_NEW_CONSOLE = 0x00000010; const int SE_WINDOW_OBJECT = 7; const int DACL_SECURITY_INFORMATION = 0x00000004; const int SDDL_REVISION_1 = 1;
    [StructLayout(LayoutKind.Sequential)] struct SECURITY_ATTRIBUTES { public uint nLength; public IntPtr lpSecurityDescriptor; [MarshalAs(UnmanagedType.Bool)] public bool bInheritHandle; }
    enum TOKEN_TYPE { TokenPrimary = 1 } enum SECURITY_IMPERSONATION_LEVEL { SecurityImpersonation } enum TOKEN_INFORMATION_CLASS { TokenSessionId = 12 }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] struct STARTUPINFO { public uint cb; public string lpReserved; public string lpDesktop; public string lpTitle; public uint dwX; public uint dwY; public uint dwXSize; public uint dwYSize; public uint dwXCountChars; public uint dwYCountChars; public uint dwFillAttribute; public uint dwFlags; public short wShowWindow; public short cbReserved2; public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError; }
    [StructLayout(LayoutKind.Sequential)] struct PROCESS_INFORMATION { public IntPtr hProcess; public IntPtr hThread; public int dwProcessId; public int dwThreadId; }
    
    const int PROCESS_QUERY_INFORMATION = 0x0400; const int TOKEN_DUPLICATE = 0x0002; const int TOKEN_QUERY = 0x0008; const int TOKEN_IMPERSONATE = 0x0004;
    
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct PROFILEINFO
    {
        public int dwSize;
        public int dwFlags;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string lpUserName;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string lpProfilePath;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string lpDefaultPath;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string lpServerName;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string lpPolicyPath;
        public IntPtr hProfile;
    }
}