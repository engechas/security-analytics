package org.opensearch.securityanalytics.ruleengine.store;

import org.opensearch.securityanalytics.ruleengine.rules.StatefulRule;
import org.opensearch.securityanalytics.ruleengine.rules.StatelessRule;

import java.util.ArrayList;
import java.util.List;

public class InMemoryRuleStore implements RuleStore {
    private List<StatelessRule> statelessRules;
    private List<StatefulRule> statefulRules;

    public InMemoryRuleStore() {
        this.statelessRules = new ArrayList<>();
        this.statefulRules = new ArrayList<>();
    }

    @Override
    public void updateStatelessRules(final List<StatelessRule> rules) {
        this.statelessRules = rules;
    }

    @Override
    public void updateStatefulRules(final List<StatefulRule> rules) {
        this.statefulRules = rules;
    }

    @Override
    public List<StatelessRule> getStatelessRules() {
        return statelessRules;
    }

    @Override
    public List<StatefulRule> getStatefulRules() {
        return statefulRules;
    }
}
