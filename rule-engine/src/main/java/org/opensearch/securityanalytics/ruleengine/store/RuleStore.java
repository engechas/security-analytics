package org.opensearch.securityanalytics.ruleengine.store;

import org.opensearch.securityanalytics.ruleengine.rules.StatefulRule;
import org.opensearch.securityanalytics.ruleengine.rules.StatelessRule;

import java.util.List;

public interface RuleStore {
    /**
     * Updates the backing store's rule set by providing the latest list of stateless rules
     *
     * @param rules - a list of the current stateless rule set
     */
    void updateStatelessRules(List<StatelessRule> rules);

    /**
     * Updates the backing store's rule set by providing the latest list of stateful rules
     *
     * @param rules - a list of the current stateful rule set
     */
    void updateStatefulRules(List<StatefulRule> rules);

    /**
     * Retrieves the list of stateless rules from the backing store
     *
     * @return - the list of stateless rules currently held by the RuleStore
     */
    List<StatelessRule> getStatelessRules();

    /**
     * Retrieves the list of stateful rules from the backing store
     *
     * @return - the list of stateful rules currently held by the RuleStore
     */
    List<StatefulRule> getStatefulRules();
}
