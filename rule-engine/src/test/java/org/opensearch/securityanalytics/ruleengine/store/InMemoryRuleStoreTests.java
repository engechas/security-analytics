package org.opensearch.securityanalytics.ruleengine.store;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.opensearch.securityanalytics.ruleengine.rules.StatefulRule;
import org.opensearch.securityanalytics.ruleengine.rules.StatelessRule;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class InMemoryRuleStoreTests {
    @Mock
    private StatelessRule statelessRule;
    @Mock
    private StatefulRule statefulRule;

    private InMemoryRuleStore ruleStore;

    @BeforeEach
    public void setup() {
        MockitoAnnotations.openMocks(this);
        this.ruleStore = new InMemoryRuleStore();
    }

    @Test
    public void testUpdateStatelessRules() {
        assertEquals(Collections.emptyList(), ruleStore.getStatelessRules());

        ruleStore.updateStatelessRules(List.of(statelessRule));
        assertEquals(List.of(statelessRule), ruleStore.getStatelessRules());
    }

    @Test
    public void testUpdateStatefulRules() {
        assertEquals(Collections.emptyList(), ruleStore.getStatefulRules());

        ruleStore.updateStatefulRules(List.of(statefulRule));
        assertEquals(List.of(statefulRule), ruleStore.getStatefulRules());
    }
}
