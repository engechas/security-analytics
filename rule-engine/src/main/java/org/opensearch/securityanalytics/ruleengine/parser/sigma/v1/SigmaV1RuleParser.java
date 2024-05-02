/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.ruleengine.parser.sigma.v1;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.securityanalytics.ruleengine.exception.RuleParseException;
import org.opensearch.securityanalytics.ruleengine.field.FieldAccessor;
import org.opensearch.securityanalytics.ruleengine.model.DataType;
import org.opensearch.securityanalytics.ruleengine.parser.RuleParser;
import org.opensearch.securityanalytics.ruleengine.provider.RuleData;
import org.opensearch.securityanalytics.ruleengine.rules.ParsedRules;
import org.opensearch.securityanalytics.ruleengine.rules.StatelessRule;
import org.opensearch.securityanalytics.ruleengine.rules.implementations.OpenSearchSigmaV1StatelessRule;
import org.opensearch.securityanalytics.ruleengine.rules.metadata.OpenSearchRuleMetadata;
import org.opensearch.securityanalytics.ruleengine.rules.metadata.SigmaV1RuleMetadata;
import org.opensearch.securityanalytics.rules.aggregation.AggregationItem;
import org.opensearch.securityanalytics.rules.condition.ConditionItem;
import org.opensearch.securityanalytics.rules.objects.SigmaCondition;
import org.opensearch.securityanalytics.rules.objects.SigmaRule;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Predicate;
import java.util.stream.Collectors;

public class SigmaV1RuleParser implements RuleParser {
    private static final Logger log = LogManager.getLogger(SigmaV1RuleParser.class);

    private final SigmaV1ConditionParser conditionParser;

    public SigmaV1RuleParser(final Map<String, String> fieldTranslations) {
        final FieldAccessor fieldAccessor = new FieldAccessor(fieldTranslations);
        this.conditionParser = new SigmaV1ConditionParser(fieldAccessor);
    }

    // Visible for testing
    SigmaV1RuleParser(final SigmaV1ConditionParser conditionParser) {
        this.conditionParser = conditionParser;
    }

    @Override
    public ParsedRules parseRules(final RuleData ruleData) {
        final SigmaRule sigmaRule = SigmaRule.fromYaml(ruleData.getRuleAsString(), true);
        final String ruleId = sigmaRule.getId().toString();
        log.info("Parsing rule with ID {}", ruleId);

        final List<Pair<ConditionItem, AggregationItem>> parsedItems = getParsedItems(sigmaRule, ruleId);
        final List<ConditionItem> conditionItems = getConditionItems(parsedItems);
        final AggregationItem aggregationItem = getAggregationItem(parsedItems);
        if (aggregationItem != null) {
            throw new UnsupportedOperationException("Aggregate rules are not yet supported");
        }

        final OpenSearchRuleMetadata openSearchRuleMetadata = new OpenSearchRuleMetadata(ruleData.getMetadata());
        final SigmaV1RuleMetadata sigmaV1RuleMetadata = new SigmaV1RuleMetadata(sigmaRule);

        final Predicate<DataType> ruleCondition = conditionParser.parseRuleCondition(conditionItems);
        final boolean isStatefulCondition = aggregationItem != null;

        final StatelessRule statelessRule = new OpenSearchSigmaV1StatelessRule(
                ruleId,
                ruleData.getEvaluationCondition(),
                ruleCondition,
                isStatefulCondition,
                openSearchRuleMetadata,
                sigmaV1RuleMetadata
        );

        return new ParsedRules(List.of(statelessRule), Collections.emptyList());
    }

    private List<Pair<ConditionItem, AggregationItem>> getParsedItems(final SigmaRule sigmaRule, final String ruleId) {
        return sigmaRule.getDetection().getParsedCondition().stream()
                .map(sigmaCondition -> parseCondition(sigmaCondition, ruleId))
                .collect(Collectors.toList());
    }

    private Pair<ConditionItem, AggregationItem> parseCondition(final SigmaCondition sigmaCondition, final String ruleId) {
        try {
            return sigmaCondition.parsed();
        } catch (final Exception e) {
            throw new RuleParseException("Exception parsing rule with ID: " + ruleId, e);
        }
    }

    private List<ConditionItem> getConditionItems(final List<Pair<ConditionItem, AggregationItem>> parsedItems) {
        return parsedItems.stream()
                .map(Pair::getLeft)
                .collect(Collectors.toList());
    }

    private AggregationItem getAggregationItem(final List<Pair<ConditionItem, AggregationItem>> parsedItems) {
        final List<AggregationItem> aggregationItems = parsedItems.stream()
                .map(Pair::getRight)
                .filter(Objects::nonNull)
                .collect(Collectors.toList());

        if (aggregationItems.size() > 1) {
            throw new RuleParseException("Expected 0 or 1 aggregations. Found " + aggregationItems.size());
        }

        return aggregationItems.isEmpty() ? null : aggregationItems.get(0);
    }
}
