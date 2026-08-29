using System;
using System.Collections.Generic;

// DeepFlowChain.cs -- Entry point for deep cross-file flow chain.
// All type/function names prefixed with Dfc.

namespace Pipeline.Entry
{
    public class DfcAuditedAttribute : Attribute { }

    public class DfcCommandParser
    {
        public static string[] Tokenize(string input)
        {
            string[] tokens = input.Trim().Split(new[] { ' ', '\t' },
                StringSplitOptions.RemoveEmptyEntries);
            return tokens;
        }

        public static string ExtractAction(string[] tokens)
        {
            if (tokens.Length == 0) return "";
            string action = tokens[0];
            for (int i = 1; i < tokens.Length; i++)
            {
                action = action + " " + tokens[i];
            }
            return action;
        }
    }

    public class DfcInputValidator
    {
        public static string ValidateLength(string input)
        {
            string validated = input;
            if (validated.Length > 4096)
                validated = validated.Substring(0, 4096);
            return validated;
        }

        public static string NormalizeWhitespace(string input)
        {
            string[] parts = input.Split(new[] { ' ' },
                StringSplitOptions.RemoveEmptyEntries);
            string normalized = string.Join(" ", parts);
            return normalized;
        }
    }

    public class DfcRequestContext
    {
        public string Action { get; set; }
        public string Origin { get; set; }

        public DfcRequestContext(string action, string origin)
        {
            Action = action;
            Origin = origin;
        }
    }

    public class DeepFlowChain
    {
        [DfcAudited]
        public static void Main(string[] args)
        {
            // SOURCE: user-controlled stdin input
            string rawInput = Console.ReadLine();

            string[] tokens = DfcCommandParser.Tokenize(rawInput);
            string action = DfcCommandParser.ExtractAction(tokens);
            string validated = DfcInputValidator.ValidateLength(action);
            string normalized = DfcInputValidator.NormalizeWhitespace(validated);

            var ctx = new DfcRequestContext(normalized, "cli");

            // Cross to helpers
            var registry = new DfcPipelineRegistry();
            registry.Register("default", ctx);
            var registeredCtx = registry.Lookup("default");

            string prefixed = DfcTransformStage.ApplyPrefix(registeredCtx);
            string wrapped = DfcTransformStage.WrapInQuotes(prefixed);

            var assembler = new DfcCommandAssembler();
            assembler.SetPayload(wrapped);
            assembler.SetTarget("cmd.exe");
            string assembled = assembler.Assemble();

            string formatted = DfcOutputFormatter.FormatForShell(assembled);

            // Cross to sink
            var executor = new DfcCommandExecutor();
            string prepared = executor.Prepare(formatted);
            string finalCommand = executor.ConstructCommand(prepared);

            var execCtx = new DfcExecutionContext();
            execCtx.SetCommand(finalCommand);
            string cmdToRun = execCtx.GetCommand();

            var launcher = new DfcProcessLauncher();
            launcher.CreateProcess(cmdToRun);
            launcher.ConfigureEnvironment();
            launcher.Launch();  // SINK: Process.Start
        }
    }
}
