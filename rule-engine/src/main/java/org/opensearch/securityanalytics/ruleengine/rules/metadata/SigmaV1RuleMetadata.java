package org.opensearch.securityanalytics.ruleengine.rules.metadata;

import org.opensearch.securityanalytics.rules.objects.SigmaRule;
import org.opensearch.securityanalytics.rules.objects.SigmaRuleTag;

import java.util.ArrayList;
import java.util.List;

public class SigmaV1RuleMetadata {
    private static final String SIGMA_RULE_TAG_AS_STRING_FORMAT = "%s.%s";

    private final String title;
    private final List<String> tags;

    public SigmaV1RuleMetadata(final SigmaRule sigmaRule) {
        this.title = sigmaRule.getTitle();
        this.tags = getTagsFromSigmaRule(sigmaRule);
    }

    public String getTitle() {
        return title;
    }

    public List<String> getTags() {
        return tags;
    }

    private List<String> getTagsFromSigmaRule(final SigmaRule sigmaRule) {
        final List<String> tags = new ArrayList<>();
        tags.add(sigmaRule.getLevel().toString());
        tags.add(sigmaRule.getLogSource().getService());
        sigmaRule.getTags().stream()
                .map(this::convertSigmaRuleTagToString)
                .forEach(tags::add);

        return tags;
    }

    private String convertSigmaRuleTagToString(final SigmaRuleTag sigmaRuleTag) {
        return String.format(SIGMA_RULE_TAG_AS_STRING_FORMAT, sigmaRuleTag.getNamespace(), sigmaRuleTag.getName());
    }
}
