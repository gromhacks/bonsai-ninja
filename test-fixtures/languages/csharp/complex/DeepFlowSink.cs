using System;
using System.Diagnostics;

// DeepFlowSink.cs -- Final execution stage. All types prefixed with Dfc.

namespace Pipeline.Sink
{
    public class DfcCommandExecutor
    {
        public string Prepare(string input)
        {
            string prepared = input.Trim();
            return prepared;
        }

        public string ConstructCommand(string prepared)
        {
            string[] parts = prepared.Split(new[] { ' ' }, 2);
            string cmd = parts[0];
            if (parts.Length > 1) cmd = cmd + " " + parts[1];
            return cmd;
        }
    }

    public class DfcExecutionContext
    {
        private string _command;

        public void SetCommand(string command)
        {
            _command = command;
        }

        public string GetCommand()
        {
            string cmd = _command;
            return cmd;
        }
    }

    public class DfcProcessLauncher
    {
        private string _commandToExecute;
        private ProcessStartInfo _startInfo;

        public void CreateProcess(string command)
        {
            _commandToExecute = command;
            string[] parts = command.Split(new[] { ' ' }, 2);
            _startInfo = new ProcessStartInfo();
            _startInfo.FileName = parts[0];
            if (parts.Length > 1)
                _startInfo.Arguments = parts[1];
        }

        public void ConfigureEnvironment()
        {
            _startInfo.UseShellExecute = false;
            _startInfo.RedirectStandardOutput = true;
            _startInfo.RedirectStandardError = true;
        }

        public void Launch()
        {
            try
            {
                // SINK: tainted data from Console.ReadLine reaches Process.Start
                string cmd = _commandToExecute;
                _startInfo.FileName = cmd;
                Process.Start(_startInfo);
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("Execution failed: " + e.Message);
            }
        }
    }
}
