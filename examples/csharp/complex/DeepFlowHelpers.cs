using System;
using System.Collections.Generic;
using System.Text;

// DeepFlowHelpers.cs -- Middleware pipeline stages. All types prefixed with Dfc.

namespace Pipeline.Helpers
{
    public class DfcPipelineRegistry
    {
        private Dictionary<string, DfcRequestContext> _store =
            new Dictionary<string, DfcRequestContext>();

        public void Register(string name, DfcRequestContext ctx)
        {
            var copy = new DfcRequestContext(ctx.Action, ctx.Origin);
            _store[name] = copy;
        }

        public DfcRequestContext Lookup(string name)
        {
            DfcRequestContext found = _store[name];
            return found;
        }
    }

    public static class DfcTransformStage
    {
        public static string ApplyPrefix(DfcRequestContext ctx)
        {
            string action = ctx.Action;
            string prefixed = "CMD:" + action;
            return prefixed;
        }

        public static string WrapInQuotes(string input)
        {
            string wrapped = "\"" + input + "\"";
            return wrapped;
        }
    }

    public class DfcCommandAssembler
    {
        private string _payload;
        private string _target;

        public void SetPayload(string payload)
        {
            _payload = payload;
        }

        public void SetTarget(string target)
        {
            _target = target;
        }

        public string Assemble()
        {
            var sb = new StringBuilder();
            sb.Append(_target);
            sb.Append(" /c ");
            sb.Append(_payload);
            string assembled = sb.ToString();
            return assembled;
        }
    }

    public static class DfcOutputFormatter
    {
        public static string FormatForShell(string input)
        {
            string shellFmt = input.Replace("\\", "\\\\");
            return shellFmt;
        }
    }
}
