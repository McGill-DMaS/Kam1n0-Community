using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using Microsoft.Deployment.WindowsInstaller;

namespace CustomActions
{
    public class KamActions
    {

        public static void main()
        {

        }


        public static void setPath(string distrPath, string setDataPath)
        {
            string confFile = distrPath + "\\kam1n0-conf.xml";
            string logFile = distrPath + "\\log4j2.xml";
            string confStr = File.ReadAllText(confFile);
            string logStr = File.ReadAllText(logFile);
            string identifier = @"$PATH_DATA$";
            confStr = confStr.Replace(identifier, setDataPath);
            logStr = logStr.Replace(identifier, setDataPath);
            File.WriteAllText(confFile, confStr);
            File.WriteAllText(logFile, logStr);
        }

        public static bool CheckIfIsIdaPluginsFolder(String selectedPath)
        {
            bool isCorrectFolder = false;
            DirectoryInfo info = new DirectoryInfo(selectedPath);
            if (!info.Name.Equals("plugins"))
                isCorrectFolder = false;
            else
            {
                var idadir = info.Parent;
                var files = idadir.GetFiles();
                foreach (var file in files)
                {
                    if (file.Name.Equals("idaq.exe"))
                    {
                        isCorrectFolder = true;
                        break;
                    }
                }
            }
            return isCorrectFolder;
        }

        [CustomAction]
        public static ActionResult ValidaIDAPRO(Session session)
        {
            string selectedVar = session["INSTALL_DIR"];
            string selectedPath = session[selectedVar];
            session.Log(selectedPath);
            if (CheckIfIsIdaPluginsFolder(selectedPath))
                session["INSTALL_DIR_VALID"] = "1";
            else
                session["INSTALL_DIR_VALID"] = "0";

            return ActionResult.Success;
        }

        [CustomAction]
        public static ActionResult UpdateConfFiles(Session session)
        {

            session.Log("here");
            session.Log("here");
            session.Log("here");

            string intallVar = session["INSTALL_DIR"];
            string installPath = session[intallVar];
            string dataVar = session["DATA_DIR"];
            string dataPath = session[dataVar];

            setPath(installPath, dataPath);

            return ActionResult.Success;
        }





    }
}
