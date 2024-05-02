package org.opensearch.securityanalytics.ruleengine.parser.sigma.v1;

import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.opensearch.securityanalytics.ruleengine.exception.RuleParseException;
import org.opensearch.securityanalytics.ruleengine.model.DataType;
import org.opensearch.securityanalytics.ruleengine.provider.RuleData;
import org.opensearch.securityanalytics.ruleengine.rules.ParsedRules;
import org.opensearch.securityanalytics.ruleengine.rules.StatelessRule;
import org.opensearch.securityanalytics.ruleengine.rules.implementations.OpenSearchSigmaV1StatelessRule;
import org.opensearch.securityanalytics.ruleengine.rules.metadata.OpenSearchRuleMetadata;
import org.opensearch.securityanalytics.rules.aggregation.AggregationItem;
import org.opensearch.securityanalytics.rules.condition.ConditionItem;
import org.opensearch.securityanalytics.rules.exceptions.SigmaConditionError;
import org.opensearch.securityanalytics.rules.objects.SigmaCondition;
import org.opensearch.securityanalytics.rules.objects.SigmaDetections;
import org.opensearch.securityanalytics.rules.objects.SigmaLevel;
import org.opensearch.securityanalytics.rules.objects.SigmaLogSource;
import org.opensearch.securityanalytics.rules.objects.SigmaRule;
import org.opensearch.securityanalytics.rules.objects.SigmaRuleTag;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Predicate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

public class SigmaV1RuleParserTests {
    private static final String RULE_AS_STRING = UUID.randomUUID().toString();
    private static final Predicate<DataType> EVALUATION_CONDITION = x -> true;
    private static final UUID RULE_ID = UUID.randomUUID();
    private static final String RULE_TITLE = UUID.randomUUID().toString();
    private static final String RULE_SEVERITY = UUID.randomUUID().toString();
    private static final String RULE_LOG_SOURCE = UUID.randomUUID().toString();
    private static final String RULE_TAG_NAMESPACE = UUID.randomUUID().toString();
    private static final String RULE_TAG_NAME = UUID.randomUUID().toString();

    @Mock
    private SigmaV1ConditionParser conditionParser;
    @Mock
    private SigmaRule sigmaRule;
    @Mock
    private SigmaDetections sigmaDetections;
    @Mock
    private SigmaCondition sigmaCondition;
    @Mock
    private AggregationItem aggregationItem;
    @Mock
    private ConditionItem conditionItem;
    @Mock
    private Predicate<DataType> ruleCondition;
    @Mock
    private SigmaLogSource sigmaLogSource;
    @Mock
    private SigmaRuleTag sigmaRuleTag;
    @Mock
    private SigmaLevel sigmaLevel;

    private SigmaV1RuleParser sigmaV1RuleParser;

    @BeforeEach
    public void setup() {
        MockitoAnnotations.openMocks(this);
        this.sigmaV1RuleParser = new SigmaV1RuleParser(conditionParser);
    }

    @AfterEach
    public void tearDown() {
        verifyNoMoreInteractions(conditionParser, sigmaRule, sigmaDetections, sigmaCondition, aggregationItem, conditionItem,
                ruleCondition, sigmaLogSource, sigmaRuleTag);
    }

    @Test
    public void testParseRules_GettingParsedConditionThrowsException_ThrowsRuleParseException() throws SigmaConditionError {
        mockCalls();
        when(sigmaCondition.parsed()).thenThrow(new RuntimeException());

        final RuleData ruleData = getRuleData();

        try (MockedStatic<SigmaRule> mockedStatic = Mockito.mockStatic(SigmaRule.class)) {
            mockedStatic.when(() -> SigmaRule.fromYaml(RULE_AS_STRING, true)).thenReturn(sigmaRule);
            assertThrows(RuleParseException.class, () -> sigmaV1RuleParser.parseRules(ruleData));
        }

        verify(sigmaRule).getDetection();
        verify(sigmaRule).getId();
        verify(sigmaDetections).getParsedCondition();
        verify(sigmaCondition).parsed();
    }

    @Test
    public void testParseRules_TooManyAggregationItems_ThrowsRuleParseException() throws SigmaConditionError {
        mockCalls();
        when(sigmaDetections.getParsedCondition()).thenReturn(List.of(sigmaCondition, sigmaCondition));

        final RuleData ruleData = getRuleData();

        try (MockedStatic<SigmaRule> mockedStatic = Mockito.mockStatic(SigmaRule.class)) {
            mockedStatic.when(() -> SigmaRule.fromYaml(RULE_AS_STRING, true)).thenReturn(sigmaRule);
            assertThrows(RuleParseException.class, () -> sigmaV1RuleParser.parseRules(ruleData));
        }

        verify(sigmaRule).getDetection();
        verify(sigmaRule).getId();
        verify(sigmaDetections).getParsedCondition();
        verify(sigmaCondition, times(2)).parsed();
    }

    @Test
    public void testParseRules_OneConditionItem_NoAggregationItem_Success() throws SigmaConditionError {
        mockCalls();
        when(sigmaCondition.parsed()).thenReturn(Pair.of(conditionItem, null));

        final RuleData ruleData = getRuleData();

        try (MockedStatic<SigmaRule> mockedStatic = Mockito.mockStatic(SigmaRule.class)) {
            mockedStatic.when(() -> SigmaRule.fromYaml(RULE_AS_STRING, true)).thenReturn(sigmaRule);
            final ParsedRules result = sigmaV1RuleParser.parseRules(ruleData);
            assertEquals(1, result.getStatelessRules().size());
            validateStatelessRule(result.getStatelessRules().get(0), false, ruleData);
            assertEquals(0, result.getStatefulRules().size());
        }

        verifyCalls(List.of(conditionItem));
    }

    @Test
    public void testParseRules_AggregationItem_ThrowsUnsupportedOperationException() throws SigmaConditionError {
        mockCalls();

        final RuleData ruleData = getRuleData();

        try (MockedStatic<SigmaRule> mockedStatic = Mockito.mockStatic(SigmaRule.class)) {
            mockedStatic.when(() -> SigmaRule.fromYaml(RULE_AS_STRING, true)).thenReturn(sigmaRule);
            assertThrows(UnsupportedOperationException.class, () -> sigmaV1RuleParser.parseRules(ruleData));
        }

        verify(sigmaRule).getDetection();
        verify(sigmaRule).getId();
        verify(sigmaDetections).getParsedCondition();
        verify(sigmaCondition).parsed();
    }

    @Test
    public void testParseRules_MultipleConditionItems_NoAggregationItem_Success() throws SigmaConditionError {
        mockCalls();
        when(sigmaDetections.getParsedCondition()).thenReturn(List.of(sigmaCondition, sigmaCondition));
        when(sigmaCondition.parsed()).thenReturn(Pair.of(conditionItem, null));
        when(conditionParser.parseRuleCondition(eq(List.of(conditionItem, conditionItem)))).thenReturn(ruleCondition);

        final RuleData ruleData = getRuleData();

        try (MockedStatic<SigmaRule> mockedStatic = Mockito.mockStatic(SigmaRule.class)) {
            mockedStatic.when(() -> SigmaRule.fromYaml(RULE_AS_STRING, true)).thenReturn(sigmaRule);
            final ParsedRules result = sigmaV1RuleParser.parseRules(ruleData);
            assertEquals(1, result.getStatelessRules().size());
            validateStatelessRule(result.getStatelessRules().get(0), false, ruleData);
            assertEquals(0, result.getStatefulRules().size());
        }

        verifyCalls(List.of(conditionItem, conditionItem));
    }

    private void mockCalls() throws SigmaConditionError {
        when(sigmaRule.getDetection()).thenReturn(sigmaDetections);
        when(sigmaRule.getId()).thenReturn(RULE_ID);
        when(sigmaRule.getTitle()).thenReturn(RULE_TITLE);
        when(sigmaRule.getLevel()).thenReturn(sigmaLevel);
        when(sigmaLevel.toString()).thenReturn(RULE_SEVERITY);
        when(sigmaRule.getLogSource()).thenReturn(sigmaLogSource);
        when(sigmaLogSource.getService()).thenReturn(RULE_LOG_SOURCE);
        when(sigmaRule.getTags()).thenReturn(List.of(sigmaRuleTag));
        when(sigmaRuleTag.getNamespace()).thenReturn(RULE_TAG_NAMESPACE);
        when(sigmaRuleTag.getName()).thenReturn(RULE_TAG_NAME);
        when(sigmaDetections.getParsedCondition()).thenReturn(List.of(sigmaCondition));
        when(sigmaCondition.parsed()).thenReturn(Pair.of(conditionItem, aggregationItem));
        when(conditionParser.parseRuleCondition(eq(List.of(conditionItem)))).thenReturn(ruleCondition);
    }

    private void validateStatelessRule(final StatelessRule statelessRule, final boolean isStatefulCondition, final RuleData ruleData) {
        assertTrue(statelessRule instanceof OpenSearchSigmaV1StatelessRule);
        final OpenSearchSigmaV1StatelessRule openSearchSigmaV1StatelessRule = (OpenSearchSigmaV1StatelessRule) statelessRule;
        assertEquals(RULE_ID.toString(), openSearchSigmaV1StatelessRule.getId());
        assertEquals(EVALUATION_CONDITION, openSearchSigmaV1StatelessRule.getEvaluationCondition());
        assertEquals(ruleCondition, openSearchSigmaV1StatelessRule.getRuleCondition());
        assertEquals(isStatefulCondition, openSearchSigmaV1StatelessRule.isStatefulCondition());
        assertEquals(ruleData.getMetadata().get(OpenSearchRuleMetadata.MONITOR_ID_FIELD),
                openSearchSigmaV1StatelessRule.getOpenSearchRuleMetadata().getMonitorId());
        assertEquals(ruleData.getMetadata().get(OpenSearchRuleMetadata.DETECTOR_NAME_FIELD),
                openSearchSigmaV1StatelessRule.getOpenSearchRuleMetadata().getDetectorName());
        assertEquals(ruleData.getMetadata().get(OpenSearchRuleMetadata.FINDINGS_INDEX_FIELD),
                openSearchSigmaV1StatelessRule.getOpenSearchRuleMetadata().getFindingsIndex());
        assertEquals(RULE_TITLE, openSearchSigmaV1StatelessRule.getSigmaV1RuleMetadata().getTitle());
        assertEquals(3, openSearchSigmaV1StatelessRule.getSigmaV1RuleMetadata().getTags().size());
        assertEquals(RULE_SEVERITY, openSearchSigmaV1StatelessRule.getSigmaV1RuleMetadata().getTags().get(0));
        assertEquals(RULE_LOG_SOURCE, openSearchSigmaV1StatelessRule.getSigmaV1RuleMetadata().getTags().get(1));
        assertEquals(RULE_TAG_NAMESPACE + "." + RULE_TAG_NAME, openSearchSigmaV1StatelessRule.getSigmaV1RuleMetadata().getTags().get(2));
    }

    private void verifyCalls(final List<ConditionItem> conditionItems) throws SigmaConditionError {
        verify(sigmaRule).getDetection();
        verify(sigmaRule).getId();
        verify(sigmaRule).getLevel();
        verify(sigmaRule).getTags();
        verify(sigmaRule).getTitle();
        verify(sigmaRule).getLogSource();
        verify(sigmaLogSource).getService();
        verify(sigmaRuleTag).getName();
        verify(sigmaRuleTag).getNamespace();
        verify(sigmaDetections).getParsedCondition();
        verify(sigmaCondition, times(conditionItems.size())).parsed();
        verify(conditionParser).parseRuleCondition(eq(conditionItems));
    }

    private RuleData getRuleData() {
        final Map<String, String> ruleMetadata = Map.of(
                OpenSearchRuleMetadata.MONITOR_ID_FIELD, UUID.randomUUID().toString(),
                OpenSearchRuleMetadata.DETECTOR_NAME_FIELD, UUID.randomUUID().toString(),
                OpenSearchRuleMetadata.FINDINGS_INDEX_FIELD, UUID.randomUUID().toString()
        );

        return new RuleData(RULE_AS_STRING, EVALUATION_CONDITION, ruleMetadata);
    }
}
