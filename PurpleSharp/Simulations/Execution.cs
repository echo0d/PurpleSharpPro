using System;
using System.Collections.ObjectModel;
using System.Management.Automation;
using System.Threading;

namespace PurpleSharp.Simulations
{
    class Execution
    {

        public static void ExecuteWmiCmd(string command, string log)
        {
            string currentPath = AppDomain.CurrentDomain.BaseDirectory;
            Lib.Logger logger = new Lib.Logger(currentPath + log);
            logger.SimulationHeader("T1047");
            logger.TimestampInfo("Using the command line to execute the technique");
            command = command == ""
                ? @"process call create ""powershell.exe"""
                : $@"process call create ""{command}""";
            try
            {
                // ExecutionHelper.StartProcessNET("wmic.exe", String.Format(@"process call create ""powershell.exe"""), logger);
                ExecutionHelper.StartProcessNET("wmic.exe", command, logger);
                logger.SimulationFinished();
                
            }
            catch (Exception ex)
            {
                logger.SimulationFailed(ex);
            }

        }
        public static void ExecutePowershellCmd(string command, string log)
        {
            string currentPath = AppDomain.CurrentDomain.BaseDirectory;
            Lib.Logger logger = new Lib.Logger(currentPath + log);
            logger.SimulationHeader("T1059.001");
            logger.TimestampInfo("Using the command line to execute the technique");
            try
            {
                string encodedPwd = "dwBoAG8AYQBtAGkA";
                command = command == "" ? encodedPwd : Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(command));
                ExecutionHelper.StartProcessApi("", $"powershell.exe -enc {command}", logger);
                logger.SimulationFinished();
            }
            catch(Exception ex)
            {
                logger.SimulationFailed(ex);
            }
            
        }

        public static void ExecutePowershellNET(string command, string log)
        {
            string currentPath = AppDomain.CurrentDomain.BaseDirectory;
            Lib.Logger logger = new Lib.Logger(currentPath + log);
            logger.SimulationHeader("T1059.001");
            logger.TimestampInfo("Using the System.Management.Automation .NET namespace to execute the technique");
            try
            {
                PowerShell pstest = PowerShell.Create();
                if (command == "")
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

        public static void WindowsCommandShell(string command, string log)
        {
            string currentPath = AppDomain.CurrentDomain.BaseDirectory;
            Lib.Logger logger = new Lib.Logger(currentPath + log);
            logger.SimulationHeader("T1059.003");
            if (command == "")
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

        public static void ServiceExecution(string binPath, string log, bool cleanup)
        {
            string currentPath = AppDomain.CurrentDomain.BaseDirectory;
            Lib.Logger logger = new Lib.Logger(currentPath + log);
            logger.SimulationHeader("T1569.002");
            logger.TimestampInfo("Create and start services using sc.exe and Net programs.");
            if (binPath == "")
            {
                binPath = "C:\\phpstudy_pro\\Extensions\\MySQL5.7.26\\bin\\mysql.exe";
            }
            try
            {
                ExecutionHelper.StartProcessApi("", $@"sc create UpdaterService binPath=""{binPath}""", logger);
                Thread.Sleep(2000);
                ExecutionHelper.StartProcessApi("", "net start UpdaterService", logger);
                Thread.Sleep(2000);
                // ExecutionHelper.StartProcessApi("", "sc start UpdaterService", logger);
                if (cleanup)
                {   
                    logger.TimestampInfo("Cleaning up services using sc.exe.");
                    ExecutionHelper.StartProcessApi("", "sc delete UpdaterService", logger);
                }
                logger.SimulationFinished();
            }
            catch (Exception ex)
            {
                logger.SimulationFailed(ex);
            }
            
        }

        public static void VisualBasic(string file, string log)
        {
            string currentPath = AppDomain.CurrentDomain.BaseDirectory;
            Lib.Logger logger = new Lib.Logger(currentPath + log);
            logger.SimulationHeader("T1059.005");
            if (file == "")
            {
                file = "./files/T1059.005.vbs";
            }
            try
            {
                // string file = "invoice0420.vbs";
                ExecutionHelper.StartProcessApi("", $"wscript.exe {file}", logger);
                logger.SimulationFinished();
            }
            catch (Exception ex)
            {
                logger.SimulationFailed(ex);
            }

        }

        public static void JScript(string file, string log)
        {
            string currentPath = AppDomain.CurrentDomain.BaseDirectory;
            Lib.Logger logger = new Lib.Logger(currentPath + log);
            logger.SimulationHeader("T1059.007");
            if (file == "")
            {
                file = "./files/T1059.007.js";
            }
            try
            {
                ExecutionHelper.StartProcessApi("", $"wscript.exe {file}", logger);
                logger.SimulationFinished();
            }
            catch (Exception ex)
            {
                logger.SimulationFailed(ex);
            }

        }

    }
}
