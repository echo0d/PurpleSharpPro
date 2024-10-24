using PurpleSharp.Lib;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading.Tasks;

namespace PurpleSharp.Simulations
{

    public class DiscoveryHelper
    {
        public static void ShareEnum(Computer computer, Lib.Logger logger)
        {
            var bufPtr = IntPtr.Zero;
            var EntriesRead = 0;
            var TotalRead = 0;
            var ResumeHandle = 0;

            const uint MAX_PREFERRED_LENGTH = 0xFFFFFFFF;

            //https://www.pinvoke.net/default.aspx/netapi32/netshareenum.html
            var res = WinAPI.NetShareEnum(computer.Fqdn, 1, ref bufPtr, MAX_PREFERRED_LENGTH, ref EntriesRead, ref TotalRead, ref ResumeHandle);
            var errorCode = Marshal.GetLastWin32Error();

            
            var Offset = bufPtr.ToInt64();

            // 0 = syccess
            if (res == 0)
            {
                DateTime dtime = DateTime.Now;
                //Console.WriteLine("{0}[{1}] Successfully enumerated shares on {2} as {3} ", "".PadLeft(4), dtime.ToString("MM/dd/yyyy HH:mm:ss"), computer.Fqdn, WindowsIdentity.GetCurrent().Name);
                logger.TimestampInfo(String.Format("Successfully enumerated shares on {0} as {1} ", computer.Fqdn, WindowsIdentity.GetCurrent().Name));
                
            }
            else
            {
                DateTime dtime = DateTime.Now;
                //Console.WriteLine("{0}[{1}] Failed to enumerate shares on {2} as {3}. Error Code:{4}", "".PadLeft(4), dtime.ToString("MM/dd/yyyy HH:mm:ss"), computer.Fqdn, WindowsIdentity.GetCurrent().Name, errorCode);
                logger.TimestampInfo(String.Format("Successfully enumerated shares on {0} as {1} ", computer.Fqdn, WindowsIdentity.GetCurrent().Name));
            }

        }

        //From SharpView
        public static void FindLocalAdminAccess(Computer computer)
        {


            var Handle = WinAPI.OpenSCManagerW($@"\\" + computer.Fqdn, "ServicesActive", 0xF003F);


            var errorCode = Marshal.GetLastWin32Error();
            if (Handle != IntPtr.Zero)
            {
                WinAPI.CloseServiceHandle(Handle);
                DateTime dtime = DateTime.Now;
                Console.WriteLine("{0}[{1}] {2} is a local admin on {3}", "".PadLeft(4), dtime.ToString("MM/dd/yyyy HH:mm:ss"), Environment.UserName, computer.Fqdn);
            }
            else
            {
                DateTime dtime = DateTime.Now;
                if (errorCode == 5) Console.WriteLine("{0}[{1}] {2} is not a local admin on {3}", "".PadLeft(4), dtime.ToString("MM/dd/yyyy HH:mm:ss"), Environment.UserName, computer.Fqdn);
                else Console.WriteLine("{0}[{1}] Could not confirm if {2} is local admin on {3}. Error Code:{4}", "".PadLeft(4), dtime.ToString("MM/dd/yyyy HH:mm:ss"), Environment.UserName, computer.Fqdn, errorCode);
            }

        }

        public static void PortScan(Computer computer, TimeSpan timeout, int[] ports, Logger logger)
        {
            IPAddress server2 = IPAddress.Parse(computer.IPv4);
            //List<int> ports = new List<int> { 21, 22, 23, 25, 80, 135, 139, 443, 445, 1433, 3306, 3389, 8080, 8000, 10000 };
            //List<int> ports = new List<int> { 135, 139, 443, 445, 1433, 3306, 3389};

            foreach (int port in ports)
            {
                //Console.WriteLine("Scanning port {0} on {1}", port, computer.Fqdn);
                logger.TimestampInfo(String.Format("Scanning port {0} on {1}", port, computer.IPv4));
                IPEndPoint remoteEP = new IPEndPoint(server2, port);
                Socket sender = new Socket(remoteEP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

                try
                {

                    var result = sender.BeginConnect(remoteEP, null, null);

                    bool success = result.AsyncWaitHandle.WaitOne(timeout, true);
                    if (success)
                    {
                        sender.EndConnect(result);
                        //Console.WriteLine("port is open on: " + remoteEP.ToString());
                        //return true;
                    }
                    else
                    {
                        sender.Close();
                        //Console.WriteLine("port is closed on: " + remoteEP.ToString());
                        //return false;
                        //throw new SocketException(10060); // Connection timed out.
                    }

                }
                catch
                {
                    //Console.WriteLine("port is closed on: " + remoteEP.ToString() + " (Exception)");
                    //DateTime dtime = DateTime.Now;
                    //Console.WriteLine("{0}[{1}] Could not perform network service scan on {2}", "".PadLeft(4), dtime.ToString("MM/dd/yyyy HH:mm:ss"), computer.Fqdn);
                    //return false;
                }
            }
            DateTime dtime = DateTime.Now;
        }

        public static void LdapQueryForObjects(Logger logger, int type=1, string user = "", string group = "")
        {
            try
            {

                PrincipalContext context = new PrincipalContext(ContextType.Domain);
                string dc = context.ConnectedServer;
                DirectoryEntry searchRoot = new DirectoryEntry("LDAP://" + dc);
                DirectorySearcher search = new DirectorySearcher();
                search = new DirectorySearcher(searchRoot);

                //users
                if (type == 1)
                {
                    search.Filter = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";
                    search.PropertiesToLoad.Add("samaccountname");
                    search.PropertiesToLoad.Add("displayname");
                }
                else if (type == 2)
                {
                    if (group.Equals(""))
                    {
                        search.Filter = "(&(objectClass=group))";
                        search.PropertiesToLoad.Add("samaccountname");
                        search.PropertiesToLoad.Add("CanonicalName");
                    }
                    else
                    {
                        //https://forums.asp.net/t/1991180.aspx?Query+AD+for+users+in+a+specific+group+by+group+name+
                        search.Filter = String.Format("(&(cn={0})(objectClass=group))", group);
                        search.PropertiesToLoad.Add("member");
                    }   
                }
                search.SizeLimit = 15;
                SearchResult result;
                SearchResultCollection resultCol = search.FindAll();

                if (resultCol != null)
                {
                    logger.TimestampInfo(String.Format("Obtained {0} results via LDAP", resultCol.Count));
                    for (int counter = 0; counter < resultCol.Count; counter++)
                    {
                        string UserNameEmailString = string.Empty;
                        result = resultCol[counter];
                        if (result.Properties.Contains("samaccountname") && result.Properties.Contains("displayname"))
                        {
                            logger.TimestampInfo((String)result.Properties["displayname"][0] + ": " + (String)result.Properties["samaccountname"][0]);
                        }
                        else if (result.Properties.Contains("samaccountname") && result.Properties.Contains("CanonicalName"))
                        {
                            logger.TimestampInfo((String)result.Properties["samaccountname"][0] + " - " + (String)result.Properties["CanonicalName"][0]);
                        }
                        else if (result.Properties.Contains("Member"))
                        {
                            logger.TimestampInfo((String)result.Properties["member"][0]);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                logger.TimestampInfo("Failed");
                logger.TimestampInfo(ex.ToString());
                logger.TimestampInfo(ex.Message.ToString());
            }
        }

    }
}