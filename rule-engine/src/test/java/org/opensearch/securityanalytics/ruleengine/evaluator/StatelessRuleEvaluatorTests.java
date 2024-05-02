package org.opensearch.securityanalytics.ruleengine.evaluator;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.opensearch.securityanalytics.ruleengine.model.DataType;
import org.opensearch.securityanalytics.ruleengine.model.Match;
import org.opensearch.securityanalytics.ruleengine.rules.StatelessRule;
import org.opensearch.securityanalytics.ruleengine.store.RuleStore;

import java.util.Collections;
import java.util.List;
import java.util.function.Predicate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

public class StatelessRuleEvaluatorTests {
    private static final Predicate<DataType> ALWAYS_TRUE = x -> true;
    private static final Predicate<DataType> ALWAYS_FALSE = x -> false;

    @Mock
    private RuleStore ruleStore;
    @Mock
    private DataType dataType;
    @Mock
    private DataType dataType2;
    @Mock
    private StatelessRule rule;
    @Mock
    private StatelessRule rule2;

    private StatelessRuleEvaluator ruleEvaluator;

    @BeforeEach
    public void setup() {
        MockitoAnnotations.openMocks(this);
        this.ruleEvaluator = new StatelessRuleEvaluator(ruleStore);
    }

    @AfterEach
    public void tearDown() {
        verifyNoMoreInteractions(ruleStore, dataType, dataType2, rule, rule2);
    }

    @Test
    public void testEvaluate_EmptyListOfData() {
        assertEquals(Collections.emptyList(), ruleEvaluator.evaluate(Collections.emptyList()));
    }

    @Test
    public void testEvaluate_NoRules() {
        when(ruleStore.getStatelessRules()).thenReturn(Collections.emptyList());

        assertEquals(Collections.emptyList(), ruleEvaluator.evaluate(List.of(dataType)));

        verify(ruleStore).getStatelessRules();
    }

    @Test
    public void testEvaluate_EvaluationConditionFalse() {
        when(ruleStore.getStatelessRules()).thenReturn(List.of(rule));
        when(rule.getEvaluationCondition()).thenReturn(ALWAYS_FALSE);

        assertEquals(Collections.emptyList(), ruleEvaluator.evaluate(List.of(dataType)));

        verify(ruleStore).getStatelessRules();
        verify(rule).getEvaluationCondition();
    }

    @Test
    public void testEvaluate_RuleConditionFalse() {
        when(ruleStore.getStatelessRules()).thenReturn(List.of(rule));
        when(rule.getEvaluationCondition()).thenReturn(ALWAYS_TRUE);
        when(rule.getRuleCondition()).thenReturn(ALWAYS_FALSE);

        assertEquals(Collections.emptyList(), ruleEvaluator.evaluate(List.of(dataType)));

        verify(ruleStore).getStatelessRules();
        verify(rule).getEvaluationCondition();
        verify(rule).getRuleCondition();
    }

    @Test
    public void testEvaluate_MatchGenerated() {
        when(ruleStore.getStatelessRules()).thenReturn(List.of(rule));
        when(rule.getEvaluationCondition()).thenReturn(ALWAYS_TRUE);
        when(rule.getRuleCondition()).thenReturn(ALWAYS_TRUE);

        final List<Match> matches = ruleEvaluator.evaluate(List.of(dataType));
        assertEquals(1, matches.size());
        assertEquals(dataType, matches.get(0).getDatum());
        assertEquals(List.of(rule), matches.get(0).getStatelessRules());
        assertEquals(Collections.emptyList(), matches.get(0).getStatefulRules());

        verify(ruleStore).getStatelessRules();
        verify(rule).getEvaluationCondition();
        verify(rule).getRuleCondition();
    }

    @Test
    public void testEvaluate_FiltersOutRuleByEvaluationCondition() {
        when(ruleStore.getStatelessRules()).thenReturn(List.of(rule, rule2));
        when(rule.getEvaluationCondition()).thenReturn(ALWAYS_TRUE);
        when(rule.getRuleCondition()).thenReturn(ALWAYS_TRUE);
        when(rule2.getEvaluationCondition()).thenReturn(ALWAYS_FALSE);

        final List<Match> matches = ruleEvaluator.evaluate(List.of(dataType));
        assertEquals(1, matches.size());
        assertEquals(dataType, matches.get(0).getDatum());
        assertEquals(List.of(rule), matches.get(0).getStatelessRules());
        assertEquals(Collections.emptyList(), matches.get(0).getStatefulRules());

        verify(ruleStore).getStatelessRules();
        verify(rule).getEvaluationCondition();
        verify(rule).getRuleCondition();
        verify(rule2).getEvaluationCondition();
    }

    @Test
    public void testEvaluate_FiltersOutRuleByRuleCondition() {
        when(ruleStore.getStatelessRules()).thenReturn(List.of(rule, rule2));
        when(rule.getEvaluationCondition()).thenReturn(ALWAYS_TRUE);
        when(rule.getRuleCondition()).thenReturn(ALWAYS_TRUE);
        when(rule2.getEvaluationCondition()).thenReturn(ALWAYS_TRUE);
        when(rule2.getRuleCondition()).thenReturn(ALWAYS_FALSE);

        final List<Match> matches = ruleEvaluator.evaluate(List.of(dataType));
        assertEquals(1, matches.size());
        assertEquals(dataType, matches.get(0).getDatum());
        assertEquals(List.of(rule), matches.get(0).getStatelessRules());
        assertEquals(Collections.emptyList(), matches.get(0).getStatefulRules());

        verify(ruleStore).getStatelessRules();
        verify(rule).getEvaluationCondition();
        verify(rule).getRuleCondition();
        verify(rule2).getEvaluationCondition();
        verify(rule2).getRuleCondition();
    }

    @Test
    public void testEvaluate_MultipleRuleMatches() {
        when(ruleStore.getStatelessRules()).thenReturn(List.of(rule, rule2));
        when(rule.getEvaluationCondition()).thenReturn(ALWAYS_TRUE);
        when(rule.getRuleCondition()).thenReturn(ALWAYS_TRUE);
        when(rule2.getEvaluationCondition()).thenReturn(ALWAYS_TRUE);
        when(rule2.getRuleCondition()).thenReturn(ALWAYS_TRUE);

        final List<Match> matches = ruleEvaluator.evaluate(List.of(dataType));
        assertEquals(1, matches.size());
        assertEquals(dataType, matches.get(0).getDatum());
        assertEquals(List.of(rule, rule2), matches.get(0).getStatelessRules());
        assertEquals(Collections.emptyList(), matches.get(0).getStatefulRules());

        verify(ruleStore).getStatelessRules();
        verify(rule).getEvaluationCondition();
        verify(rule).getRuleCondition();
        verify(rule2).getEvaluationCondition();
        verify(rule2).getRuleCondition();
    }

    @Test
    public void testEvaluate_MultipleDataTypes_NoRuleMatches() {
        when(ruleStore.getStatelessRules()).thenReturn(List.of(rule));
        when(rule.getEvaluationCondition()).thenReturn(ALWAYS_FALSE);

        assertEquals(Collections.emptyList(), ruleEvaluator.evaluate(List.of(dataType, dataType2)));

        verify(ruleStore).getStatelessRules();
        verify(rule, times(2)).getEvaluationCondition();
    }

    @Test
    public void testEvaluate_MultipleDataTypes_OneRuleMatch() {
        when(ruleStore.getStatelessRules()).thenReturn(List.of(rule, rule2));
        when(rule.getEvaluationCondition()).thenReturn(ALWAYS_FALSE);
        when(rule2.getEvaluationCondition()).thenReturn(ALWAYS_FALSE)
                .thenReturn(ALWAYS_TRUE);
        when(rule2.getRuleCondition()).thenReturn(ALWAYS_TRUE);

        final List<Match> matches = ruleEvaluator.evaluate(List.of(dataType, dataType2));
        assertEquals(1, matches.size());
        assertEquals(dataType2, matches.get(0).getDatum());
        assertEquals(List.of(rule2), matches.get(0).getStatelessRules());
        assertEquals(Collections.emptyList(), matches.get(0).getStatefulRules());

        verify(ruleStore).getStatelessRules();
        verify(rule, times(2)).getEvaluationCondition();
        verify(rule2, times(2)).getEvaluationCondition();
        verify(rule2).getRuleCondition();
    }

    @Test
    public void testEvaluate_MultipleDataTypes_BothRulesMatch() {
        when(ruleStore.getStatelessRules()).thenReturn(List.of(rule, rule2));
        when(rule.getEvaluationCondition()).thenReturn(ALWAYS_FALSE)
                .thenReturn(ALWAYS_TRUE);
        when(rule.getRuleCondition()).thenReturn(ALWAYS_TRUE);
        when(rule2.getEvaluationCondition()).thenReturn(ALWAYS_FALSE)
                .thenReturn(ALWAYS_TRUE);
        when(rule2.getRuleCondition()).thenReturn(ALWAYS_TRUE);

        final List<Match> matches = ruleEvaluator.evaluate(List.of(dataType, dataType2));
        assertEquals(1, matches.size());
        assertEquals(dataType2, matches.get(0).getDatum());
        assertEquals(List.of(rule, rule2), matches.get(0).getStatelessRules());
        assertEquals(Collections.emptyList(), matches.get(0).getStatefulRules());

        verify(ruleStore).getStatelessRules();
        verify(rule, times(2)).getEvaluationCondition();
        verify(rule).getRuleCondition();
        verify(rule2, times(2)).getEvaluationCondition();
        verify(rule2).getRuleCondition();
    }

    @Test
    public void testEvaluate_MultipleDataTypes_OneMatchForEach() {
        when(ruleStore.getStatelessRules()).thenReturn(List.of(rule, rule2));
        when(rule.getEvaluationCondition()).thenReturn(ALWAYS_TRUE)
                .thenReturn(ALWAYS_FALSE);
        when(rule.getRuleCondition()).thenReturn(ALWAYS_TRUE);
        when(rule2.getEvaluationCondition()).thenReturn(ALWAYS_FALSE)
                .thenReturn(ALWAYS_TRUE);
        when(rule2.getRuleCondition()).thenReturn(ALWAYS_TRUE);

        final List<Match> matches = ruleEvaluator.evaluate(List.of(dataType, dataType2));
        assertEquals(2, matches.size());
        assertEquals(dataType, matches.get(0).getDatum());
        assertEquals(List.of(rule), matches.get(0).getStatelessRules());
        assertEquals(Collections.emptyList(), matches.get(0).getStatefulRules());
        assertEquals(dataType2, matches.get(1).getDatum());
        assertEquals(List.of(rule2), matches.get(1).getStatelessRules());
        assertEquals(Collections.emptyList(), matches.get(1).getStatefulRules());

        verify(ruleStore).getStatelessRules();
        verify(rule, times(2)).getEvaluationCondition();
        verify(rule).getRuleCondition();
        verify(rule2, times(2)).getEvaluationCondition();
        verify(rule2).getRuleCondition();
    }

    @Test
    public void testEvaluate_MultipleDataTypes_FullMatch() {
        when(ruleStore.getStatelessRules()).thenReturn(List.of(rule, rule2));
        when(rule.getEvaluationCondition()).thenReturn(ALWAYS_TRUE);
        when(rule.getRuleCondition()).thenReturn(ALWAYS_TRUE);
        when(rule2.getEvaluationCondition()).thenReturn(ALWAYS_TRUE);
        when(rule2.getRuleCondition()).thenReturn(ALWAYS_TRUE);

        final List<Match> matches = ruleEvaluator.evaluate(List.of(dataType, dataType2));
        assertEquals(2, matches.size());
        assertEquals(dataType, matches.get(0).getDatum());
        assertEquals(List.of(rule, rule2), matches.get(0).getStatelessRules());
        assertEquals(Collections.emptyList(), matches.get(0).getStatefulRules());
        assertEquals(dataType2, matches.get(1).getDatum());
        assertEquals(List.of(rule, rule2), matches.get(1).getStatelessRules());
        assertEquals(Collections.emptyList(), matches.get(1).getStatefulRules());

        verify(ruleStore).getStatelessRules();
        verify(rule, times(2)).getEvaluationCondition();
        verify(rule, times(2)).getRuleCondition();
        verify(rule2, times(2)).getEvaluationCondition();
        verify(rule2, times(2)).getRuleCondition();
    }
}
