/**
 * Compiler architecture test cases for the tree-sitter-sast flow engine.
 *
 * Each section tests a specific capability with both positive (flow expected)
 * and negative (no flow expected) scenarios.
 */
using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Collections.Generic;

namespace CompilerTests
{
    public class Tests
    {
        // -------------------------------------------------------------------
        // 1. BRANCH-AWARE KILL ANALYSIS
        // -------------------------------------------------------------------

        // [NO FLOW EXPECTED] Both branches sanitize
        public void BranchKillBothPaths(string userInput)
        {
            string cmd;
            if (userInput.Length > 100)
                cmd = "default_command";
            else
                cmd = "safe_fallback";
            Process.Start(cmd); // safe
        }

        // [FLOW EXPECTED] Only one branch kills taint
        public void BranchKillOnePath(string userInput)
        {
            var cmd = userInput;
            if (cmd.Length > 100)
                cmd = "truncated";
            // else: cmd still holds userInput
            Process.Start(cmd); // tainted
        }

        // [FLOW EXPECTED] Switch without default
        public void BranchKillSwitch(string userInput)
        {
            var query = userInput;
            switch (query[0])
            {
                case 'a':
                    query = "SELECT * FROM a";
                    break;
                case 'b':
                    query = "SELECT * FROM b";
                    break;
                // no default: query keeps userInput
            }
            var conn = new SqlConnection("Server=.;Database=test");
            new SqlCommand(query, conn).ExecuteNonQuery();
        }


        // -------------------------------------------------------------------
        // 2. INTERPROCEDURAL KILL (2+ levels deep)
        // -------------------------------------------------------------------

        private string Sanitize(string value)
        {
            return value.Replace("'", "").Replace(";", "").Replace("--", "");
        }

        private string WrapSanitize(string value)
        {
            return Sanitize(value);
        }

        // [NO FLOW EXPECTED] Sanitizer applied
        public void InterproceduralKillDirect(string userInput)
        {
            var clean = Sanitize(userInput);
            var conn = new SqlConnection("Server=.;Database=test");
            new SqlCommand("SELECT * FROM t WHERE x = '" + clean + "'", conn).ExecuteNonQuery();
        }

        // [NO FLOW EXPECTED] Sanitizer 2 levels deep
        public void InterproceduralKillTwoLevels(string userInput)
        {
            var clean = WrapSanitize(userInput);
            var conn = new SqlConnection("Server=.;Database=test");
            new SqlCommand("SELECT * FROM t WHERE x = '" + clean + "'", conn).ExecuteNonQuery();
        }

        // [FLOW EXPECTED] No sanitizer
        public void InterproceduralNoKill(string userInput)
        {
            var conn = new SqlConnection("Server=.;Database=test");
            new SqlCommand("SELECT * FROM t WHERE x = '" + userInput + "'", conn).ExecuteNonQuery();
        }


        // -------------------------------------------------------------------
        // 3. FIELD-SENSITIVE TRACKING
        // -------------------------------------------------------------------

        class Config
        {
            public string Command { get; set; } = "";
            public string Label { get; set; } = "";
        }

        // [FLOW EXPECTED] Tainted field
        public void FieldSensitiveTainted(string userInput)
        {
            var cfg = new Config { Command = userInput, Label = "safe" };
            Process.Start(cfg.Command);
        }

        // [NO FLOW EXPECTED] Safe field only
        public void FieldSensitiveSafe(string userInput)
        {
            var cfg = new Config { Command = userInput, Label = "safe" };
            Process.Start(cfg.Label);
        }

        // [NO FLOW EXPECTED] Tainted field overwritten
        public void FieldSensitiveOverwrite(string userInput)
        {
            var cfg = new Config { Command = userInput };
            cfg.Command = "hardcoded_safe";
            Process.Start(cfg.Command);
        }


        // -------------------------------------------------------------------
        // 4. EXCEPTION CHAIN TAINT
        // -------------------------------------------------------------------

        // [FLOW EXPECTED] Taint through exception
        public void ExceptionTaint(string userInput)
        {
            try
            {
                throw new InvalidOperationException("Invalid: " + userInput);
            }
            catch (InvalidOperationException e)
            {
                Process.Start(e.Message); // tainted
            }
        }


        // -------------------------------------------------------------------
        // 5. VIRTUAL DISPATCH (polymorphism)
        // -------------------------------------------------------------------

        interface IExecutor
        {
            void Execute(string cmd);
        }

        class SafeExecutor : IExecutor
        {
            public void Execute(string cmd)
            {
                Console.WriteLine("Would execute: " + cmd); // safe
            }
        }

        class UnsafeExecutor : IExecutor
        {
            public void Execute(string cmd)
            {
                Process.Start(cmd); // dangerous
            }
        }

        // [FLOW EXPECTED]
        public void TypeTrackedUnsafe(string userInput)
        {
            IExecutor executor = new UnsafeExecutor();
            executor.Execute(userInput);
        }

        // [NO FLOW EXPECTED]
        public void TypeTrackedSafe(string userInput)
        {
            IExecutor executor = new SafeExecutor();
            executor.Execute(userInput);
        }


        // -------------------------------------------------------------------
        // 6. ASYNC/AWAIT TAINT
        // -------------------------------------------------------------------

        // [FLOW EXPECTED] Taint survives await
        public async System.Threading.Tasks.Task AsyncTaint(string userInput)
        {
            var data = await System.Threading.Tasks.Task.FromResult(userInput);
            Process.Start(data);
        }


        // -------------------------------------------------------------------
        // 7. LINQ TAINT
        // -------------------------------------------------------------------

        // [FLOW EXPECTED] Taint flows through LINQ
        public void LinqTaint(string userInput)
        {
            var inputs = new List<string> { userInput, "safe" };
            var result = string.Join(" ", inputs.Where(s => s.Length > 0));
            Process.Start(result);
        }


        // -------------------------------------------------------------------
        // 8. PARAMETER SOURCE SYNTHESIS
        // -------------------------------------------------------------------

        // [FLOW EXPECTED] External entry point
        public void HandleWebhook(string payload, string signature)
        {
            Process.Start("process " + payload);
        }


        // -------------------------------------------------------------------
        // 9. CROSS-METHOD CLASS FIELD TAINT
        // -------------------------------------------------------------------

        class Pipeline
        {
            private string _data = "";

            public void Ingest(string raw)
            {
                _data = raw;
            }

            public void Process()
            {
                System.Diagnostics.Process.Start(_data);
            }
        }

        // [FLOW EXPECTED]
        public void CrossMethodFieldTaint(string userInput)
        {
            var p = new Pipeline();
            p.Ingest(userInput);
            p.Process();
        }


        // -------------------------------------------------------------------
        // 10. DELEGATE TAINT
        // -------------------------------------------------------------------

        // [FLOW EXPECTED] Taint flows through delegate
        public void DelegateTaint(string userInput)
        {
            Action<string> process = (cmd) => Process.Start(cmd);
            process(userInput);
        }


        // -------------------------------------------------------------------
        // 11. STRING INTERPOLATION
        // -------------------------------------------------------------------

        // [FLOW EXPECTED] Taint in interpolated string
        public void InterpolationTaint(string userInput)
        {
            var query = $"SELECT * FROM users WHERE name = '{userInput}'";
            var conn = new SqlConnection("Server=.;Database=test");
            new SqlCommand(query, conn).ExecuteNonQuery();
        }


        // -------------------------------------------------------------------
        // 12. CONTAINER APPEND
        // -------------------------------------------------------------------

        // [FLOW EXPECTED] Taint through List.Add
        public void ContainerAppendTainted(string userInput)
        {
            var parts = new List<string>();
            parts.Add(userInput);
            var query = string.Join(" ", parts);
            var conn = new SqlConnection("Server=.;Database=test");
            new SqlCommand(query, conn).ExecuteNonQuery();
        }
    }
}
