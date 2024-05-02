package org.opensearch.securityanalytics.ruleengine.rules.implementations;

import org.opensearch.securityanalytics.ruleengine.model.DataType;
import org.opensearch.securityanalytics.ruleengine.rules.StatelessRule;
import org.opensearch.securityanalytics.ruleengine.rules.metadata.OpenSearchRuleMetadata;
import org.opensearch.securityanalytics.ruleengine.rules.metadata.SigmaV1RuleMetadata;

import java.util.function.Predicate;

public class OpenSearchSigmaV1StatelessRule extends StatelessRule {
    private OpenSearchRuleMetadata openSearchRuleMetadata;
    private SigmaV1RuleMetadata sigmaV1RuleMetadata;

    public OpenSearchSigmaV1StatelessRule(final String id,
                                          final Predicate<DataType> evaluationCondition,
                                          final Predicate<DataType> ruleCondition,
                                          final boolean isStatefulCondition,
                                          final OpenSearchRuleMetadata openSearchRuleMetadata,
                                          final SigmaV1RuleMetadata sigmaV1RuleMetadata) {
        super(id, evaluationCondition, ruleCondition, isStatefulCondition);
        this.openSearchRuleMetadata = openSearchRuleMetadata;
        this.sigmaV1RuleMetadata = sigmaV1RuleMetadata;
    }

    public OpenSearchRuleMetadata getOpenSearchRuleMetadata() {
        return openSearchRuleMetadata;
    }

    public SigmaV1RuleMetadata getSigmaV1RuleMetadata() {
        return sigmaV1RuleMetadata;
    }
}
