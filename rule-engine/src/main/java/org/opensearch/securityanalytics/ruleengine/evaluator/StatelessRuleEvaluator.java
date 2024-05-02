/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.ruleengine.evaluator;

import org.opensearch.securityanalytics.ruleengine.model.DataType;
import org.opensearch.securityanalytics.ruleengine.model.Match;
import org.opensearch.securityanalytics.ruleengine.rules.StatelessRule;
import org.opensearch.securityanalytics.ruleengine.store.RuleStore;

import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

public class StatelessRuleEvaluator implements RuleEvaluator<DataType> {
    private final RuleStore ruleStore;

    public StatelessRuleEvaluator(final RuleStore ruleStore) {
        this.ruleStore = ruleStore;
    }

    @Override
    public List<Match> evaluate(final List<DataType> data) {
        if (data.isEmpty()) {
            return Collections.emptyList();
        }

        final List<StatelessRule> rules = ruleStore.getStatelessRules();
        if (rules.isEmpty()) {
            return Collections.emptyList();
        }

        return data.stream()
                .map(datum -> evaluateRules(datum, rules))
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    private Match evaluateRules(final DataType datum, final List<StatelessRule> rules) {
        final List<StatelessRule> ruleMatches = rules.stream()
                .filter(rule -> rule.getEvaluationCondition().test(datum))
                .filter(rule -> rule.getRuleCondition().test(datum))
                .collect(Collectors.toList());

        if (ruleMatches.isEmpty()) {
            return null;
        }

        final Match match = new Match(datum);
        match.addStatelessRules(ruleMatches);

        return match;
    }
}
