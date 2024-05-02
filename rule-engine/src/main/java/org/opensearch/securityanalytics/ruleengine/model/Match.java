/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.ruleengine.model;

import org.opensearch.securityanalytics.ruleengine.rules.StatefulRule;
import org.opensearch.securityanalytics.ruleengine.rules.StatelessRule;

import java.util.ArrayList;
import java.util.List;

public class Match {
    private final DataType datum;
    private final List<StatelessRule> statelessRules;
    private final List<StatefulRule> statefulRules;

    public Match(final DataType datum) {
        this.datum = datum;
        this.statelessRules = new ArrayList<>();
        this.statefulRules = new ArrayList<>();
    }

    public void addStatelessRules(final List<StatelessRule> rules) {
        statelessRules.addAll(rules);
    }

    public void addStatefulRules(final List<StatefulRule> rules) {
        statefulRules.addAll(rules);
    }

    public DataType getDatum() {
        return datum;
    }

    public List<StatelessRule> getStatelessRules() {
        return statelessRules;
    }

    public List<StatefulRule> getStatefulRules() {
        return statefulRules;
    }
}
