import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.util.Map;

@Retention(RetentionPolicy.RUNTIME)
@interface DfcWrappedAudited {}

public class DecoratedDeepFlowEntry {
    @DfcWrappedAudited
    public static String runDecorated(String rawInput) {
        DeepFlowChain.DfcCommandParser parser = new DeepFlowChain.DfcCommandParser();
        DeepFlowChain.DfcInputValidator validator = new DeepFlowChain.DfcInputValidator();

        Map<String, String> tokens = parser.tokenize(rawInput);
        Map<String, String> descriptor = parser.normalize(tokens);
        Map<String, String> validated = validator.checkFormat(descriptor);
        DfcRequestContext ctx = DeepFlowChain.dfcBuildRequest(validated);
        DfcRequestContext processed = DeepFlowChain.dfcApplyMiddleware(ctx);
        return DeepFlowChain.dfcDispatchToExecutor(processed);
    }
}
