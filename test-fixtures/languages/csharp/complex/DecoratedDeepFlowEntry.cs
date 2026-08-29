using System;

namespace Pipeline.Entry
{
    public class DfcWrappedAuditedAttribute : Attribute { }

    public class DecoratedDeepFlowEntry
    {
        [DfcWrappedAudited]
        public void RunDecorated(string rawInput)
        {
            string[] tokens = DfcCommandParser.Tokenize(rawInput);
            string action = DfcCommandParser.ExtractAction(tokens);
            string validated = DfcInputValidator.ValidateLength(action);
            string normalized = DfcInputValidator.NormalizeWhitespace(validated);

            var ctx = new DfcRequestContext(normalized, "cli");
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

            var executor = new DfcCommandExecutor();
            string prepared = executor.Prepare(formatted);
            string finalCommand = executor.ConstructCommand(prepared);

            var execCtx = new DfcExecutionContext();
            execCtx.SetCommand(finalCommand);
            string cmdToRun = execCtx.GetCommand();

            var launcher = new DfcProcessLauncher();
            launcher.CreateProcess(cmdToRun);
            launcher.ConfigureEnvironment();
            launcher.Launch();
        }
    }
}
