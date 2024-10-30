using System;
using System.Collections.ObjectModel;
using System.Management.Automation;
using System.Threading;
using PurpleSharp.Lib;

namespace PurpleSharp.Simulations
{
    class Execution
    {

        public static void ExecuteWmiCmd(PlaybookTask playbookTask, string log)
        {
            string currentPath = AppDomain.CurrentDomain.BaseDirectory;
            Lib.Logger logger = new Lib.Logger(currentPath + log);
            logger.SimulationHeader("T1047");
            logger.TimestampInfo("Using the command line to execute the technique");
            string filePath = playbookTask.filePath == null
                ? @"process call create ""powershell.exe"""
                : $@"process call create ""{playbookTask.filePath}""";
            try
            {
                // ExecutionHelper.StartProcessNET("wmic.exe", String.Format(@"process call create ""powershell.exe"""), logger);
                ExecutionHelper.StartProcessNET("wmic.exe", filePath, logger);
                logger.SimulationFinished();
                
            }
            catch (Exception ex)
            {
                logger.SimulationFailed(ex);
            }

        }
        public static void ExecutePowershellCmd(PlaybookTask playbookTask, string log)
        {
            string currentPath = AppDomain.CurrentDomain.BaseDirectory;
            Lib.Logger logger = new Lib.Logger(currentPath + log);
            logger.SimulationHeader("T1059.001");
            logger.TimestampInfo("Using the command line to execute the technique");
            try
            {
                string encodedPwd = "dwBoAG8AYQBtAGkA";
                string command = playbookTask.command == null ? encodedPwd : Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(playbookTask.command));
                ExecutionHelper.StartProcessApi("", $"powershell.exe -enc {command}", logger);
                logger.SimulationFinished();
            }
            catch(Exception ex)
            {
                logger.SimulationFailed(ex);
            }
            
        }

        public static void ExecutePowershellNET(PlaybookTask playbookTask, string log)
        {
            string currentPath = AppDomain.CurrentDomain.BaseDirectory;
            Lib.Logger logger = new Lib.Logger(currentPath + log);
            logger.SimulationHeader("T1059.001");
            logger.TimestampInfo("Using the System.Management.Automation .NET namespace to execute the technique");
            try
            {
                PowerShell pstest = PowerShell.Create();
                string command = playbookTask.command;
                if (command == null)
                {
                    command =  "whoami";
                }
                // script = System.Text.Encoding.Unicode.GetString(System.Convert.FromBase64String(script));
                pstest.AddScript(command);
                Collection<PSObject> output = null;
                output = pstest.Invoke();
                logger.TimestampInfo("Succesfully invoked a PowerShell script using .NET");
                logger.SimulationFinished();
                
            }
            catch (Exception ex)
            {
                logger.SimulationFailed(ex);
            }
            
        }

        public static void WindowsCommandShell(PlaybookTask playbookTask, string log)
        {
            string currentPath = AppDomain.CurrentDomain.BaseDirectory;
            Lib.Logger logger = new Lib.Logger(currentPath + log);
            logger.SimulationHeader("T1059.003");
            string command = playbookTask.command;
            if (command == null)
            {
                command = "whoami";
            }
            try
            {
                ExecutionHelper.StartProcessApi("", $"cmd.exe /C {command}", logger);
                logger.SimulationFinished();
            }
            catch (Exception ex)
            {
                logger.SimulationFailed(ex);
            }

        }

        public static void ServiceExecution(PlaybookTask playbookTask, string log)
        {
            string currentPath = AppDomain.CurrentDomain.BaseDirectory;
            Lib.Logger logger = new Lib.Logger(currentPath + log);
            logger.SimulationHeader("T1569.002");
            logger.TimestampInfo("Create and start services using sc.exe and Net programs.");
            string serviceName = playbookTask.serviceName;
            string servicePath = playbookTask.serviceName;
            bool cleanup = playbookTask.cleanup;
            if(serviceName == null)
            {
                serviceName = "UpdaterService";
            }
            if (servicePath == null)
            {
                servicePath = "C:\\phpstudy_pro\\Extensions\\MySQL5.7.26\\bin\\mysql.exe";
            }
            try
            {
                ExecutionHelper.StartProcessApi("", $@"sc create ""{serviceName}"" binPath=""{servicePath}""", logger);
                Thread.Sleep(2000);
                ExecutionHelper.StartProcessApi("", $@"net start ""{serviceName}""", logger);
                Thread.Sleep(2000);
                // ExecutionHelper.StartProcessApi("", "sc start UpdaterService", logger);
                if (cleanup)
                {   
                    logger.TimestampInfo("Cleaning up services using sc.exe.");
                    ExecutionHelper.StartProcessApi("", $@"sc delete ""{serviceName}""", logger);
                }
                logger.SimulationFinished();
            }
            catch (Exception ex)
            {
                logger.SimulationFailed(ex);
            }
            
        }

        public static void VisualBasic(PlaybookTask playbookTask, string log)
        {
            string currentPath = AppDomain.CurrentDomain.BaseDirectory;
            Lib.Logger logger = new Lib.Logger(currentPath + log);
            logger.SimulationHeader("T1059.005");
            string filePath = playbookTask.filePath;
            if (filePath == null)
            {
                filePath = "./files/T1059.005.vbs";
            }
            try
            {
                // string file = "invoice0420.vbs";
                ExecutionHelper.StartProcessApi("", $"wscript.exe {filePath}", logger);
                logger.SimulationFinished();
            }
            catch (Exception ex)
            {
                logger.SimulationFailed(ex);
            }

        }

        public static void JScript(PlaybookTask playbookTask, string log)
        {
            string currentPath = AppDomain.CurrentDomain.BaseDirectory;
            Lib.Logger logger = new Lib.Logger(currentPath + log);
            logger.SimulationHeader("T1059.007");
            string filePath = playbookTask.filePath;
            if (filePath == null)
            {
                filePath = "./files/T1059.007.js";
            }
            try
            {
                ExecutionHelper.StartProcessApi("", $"wscript.exe {filePath}", logger);
                logger.SimulationFinished();
            }
            catch (Exception ex)
            {
                logger.SimulationFailed(ex);
            }

        }

    }
}
