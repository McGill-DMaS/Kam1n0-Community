using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Diagnostics;
using Microsoft.Tools.WindowsInstallerXml.Bootstrapper;
using System.Windows.Threading;

namespace PluginInstallerUI
{
    public class InstallerApp : BootstrapperApplication
    {
        // global dispatcher
        static public Dispatcher BootstrapperDispatcher { get; private set; }

        // entry point for custom UI
        protected override void Run()
        {
            BootstrapperDispatcher = Dispatcher.CurrentDispatcher;
            MainWindow form = new MainWindow(this);
            form.Closed += (sender, e) => { this.Engine.Quit(0); Environment.Exit(0); };
            form.ShowDialog();

            Dispatcher.Run();
        }
    }
}
