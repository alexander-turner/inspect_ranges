// vsockd v3 service entrypoint for Windows (ServiceBase; -console for
// foreground debugging, -version prints the version/protocol).

using System;
using System.ServiceProcess;
using System.Threading;

namespace VsockD
{
    sealed class DaemonService : ServiceBase
    {
        public DaemonService() { ServiceName = "vsockd"; }

        protected override void OnStart(string[] args)
        {
            Thread t = new Thread(Daemon.ListenLoop);
            t.IsBackground = true;
            t.Start();
        }

        protected override void OnStop() { }
    }

    static class Program
    {
        static int Main(string[] args)
        {
            if (args.Length > 0 && args[0] == "-version")
            {
                Console.WriteLine(Daemon.Version + " protocol=" + Wire.ProtocolVersion);
                return 0;
            }
            if (args.Length > 0 && args[0] == "-console")
            {
                Daemon.Log("console mode start");
                Daemon.ListenLoop();
                return 0;
            }
            ServiceBase.Run(new DaemonService());
            return 0;
        }
    }
}
