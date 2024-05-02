package org.opensearch.securityanalytics.ruleengine.parser.sigma.v1;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.opensearch.securityanalytics.ruleengine.RuleEngineTestHelpers;
import org.opensearch.securityanalytics.ruleengine.exception.RuleParseException;
import org.opensearch.securityanalytics.ruleengine.model.DataType;
import org.opensearch.securityanalytics.rules.condition.ConditionAND;
import org.opensearch.securityanalytics.rules.condition.ConditionFieldEqualsValueExpression;
import org.opensearch.securityanalytics.rules.condition.ConditionIdentifier;
import org.opensearch.securityanalytics.rules.condition.ConditionItem;
import org.opensearch.securityanalytics.rules.condition.ConditionNOT;
import org.opensearch.securityanalytics.rules.condition.ConditionOR;
import org.opensearch.securityanalytics.rules.condition.ConditionValueExpression;
import org.opensearch.securityanalytics.rules.types.SigmaBool;
import org.opensearch.securityanalytics.rules.types.SigmaString;
import org.opensearch.securityanalytics.rules.utils.AnyOneOf;
import org.opensearch.securityanalytics.rules.utils.Either;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Predicate;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

public class SigmaV1ConditionParserTests {
    private static final String FIELD_NAME1 = UUID.randomUUID().toString();
    private static final String FIELD_NAME2 = UUID.randomUUID().toString();
    private static final String FIELD_NAME3 = UUID.randomUUID().toString();
    private static final String FIELD_VALUE1 = UUID.randomUUID().toString();
    private static final String FIELD_VALUE2 = UUID.randomUUID().toString();
    private static final String FIELD_VALUE3 = UUID.randomUUID().toString();
    private static final Map<String, Object> MATCHING_DATA_TYPE_FIELDS = Map.of(
            FIELD_NAME1, FIELD_VALUE1,
            FIELD_NAME2, FIELD_VALUE2,
            FIELD_NAME3, FIELD_VALUE3
    );
    private static final Map<String, Object> NON_MATCHING_DATA_TYPE_FIELDS = Map.of(
            FIELD_NAME1, UUID.randomUUID().toString(),
            FIELD_NAME2, UUID.randomUUID().toString(),
            FIELD_NAME3, UUID.randomUUID().toString()
    );

    @Mock
    private SigmaV1LeafConditionParser sigmaV1LeafConditionParser;

    private SigmaV1ConditionParser sigmaV1ConditionParser;

    @BeforeEach
    public void setup() {
        MockitoAnnotations.openMocks(this);
        this.sigmaV1ConditionParser = new SigmaV1ConditionParser(sigmaV1LeafConditionParser);
    }

    @AfterEach
    public void tearDown() {
        verifyNoMoreInteractions(sigmaV1LeafConditionParser);
    }

    @Test
    public void testParseRuleCondition_SingleFieldEqualsCondition() {
        final DataType matchingDataType = RuleEngineTestHelpers.getDataType(Map.of(FIELD_NAME1, Boolean.TRUE));
        final DataType nonMatchingDataType = RuleEngineTestHelpers.getDataType(Map.of(FIELD_NAME1, Boolean.FALSE));

        final ConditionFieldEqualsValueExpression condition = new ConditionFieldEqualsValueExpression(FIELD_NAME1, new SigmaBool(Boolean.TRUE));
        when(sigmaV1LeafConditionParser.parseLeafCondition(eq(condition))).thenReturn(x -> Boolean.TRUE.equals(x.getValue(FIELD_NAME1)));

        final Predicate<DataType> result = sigmaV1ConditionParser.parseRuleCondition(List.of(condition));
        assertTrue(result.test(matchingDataType));
        assertFalse(result.test(nonMatchingDataType));

        verify(sigmaV1LeafConditionParser).parseLeafCondition(eq(condition));
    }

    @Test
    public void testParseRuleCondition_KeywordSelection_ThrowsUnsupportedOperationException() {
        final ConditionValueExpression condition = new ConditionValueExpression(new SigmaString(UUID.randomUUID().toString()));
        assertThrows(UnsupportedOperationException.class, () -> sigmaV1ConditionParser.parseRuleCondition(List.of(condition)));
    }

    @Test
    public void testParseRuleCondition_ConditionIdentifier_ThrowsRuleParseException() {
        final Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String> arg1 = Either.right(UUID.randomUUID().toString());
        final ConditionIdentifier condition = new ConditionIdentifier(List.of(arg1));
        assertThrows(RuleParseException.class, () -> sigmaV1ConditionParser.parseRuleCondition(List.of(condition)));
    }

    @Test
    public void testParseRuleCondition_AndCondition() {
        final DataType matchingDataType = RuleEngineTestHelpers.getDataType(MATCHING_DATA_TYPE_FIELDS);
        final DataType leftNonMatchingDataType = RuleEngineTestHelpers.getDataType(Map.of(
                FIELD_NAME1, UUID.randomUUID().toString(),
                FIELD_NAME2, FIELD_VALUE2
        ));
        final DataType rightNonMatchingDataType = RuleEngineTestHelpers.getDataType(Map.of(
                FIELD_NAME1, FIELD_VALUE1,
                FIELD_NAME2, UUID.randomUUID().toString()
        ));
        final DataType nonMatchingDataType = RuleEngineTestHelpers.getDataType(NON_MATCHING_DATA_TYPE_FIELDS);

        final ConditionFieldEqualsValueExpression condition1 = new ConditionFieldEqualsValueExpression(FIELD_NAME1, new SigmaString(FIELD_VALUE1));
        final Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String> arg1 = Either.left(AnyOneOf.middleVal(condition1));
        final ConditionFieldEqualsValueExpression condition2 = new ConditionFieldEqualsValueExpression(FIELD_NAME2, new SigmaString(FIELD_VALUE2));
        final Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String> arg2 = Either.left(AnyOneOf.middleVal(condition2));
        final ConditionAND condition = new ConditionAND(false, List.of(arg1, arg2));

        when(sigmaV1LeafConditionParser.parseLeafCondition(eq(condition1))).thenReturn(x -> FIELD_VALUE1.equals(x.getValue(FIELD_NAME1)));
        when(sigmaV1LeafConditionParser.parseLeafCondition(eq(condition2))).thenReturn(x -> FIELD_VALUE2.equals(x.getValue(FIELD_NAME2)));

        final Predicate<DataType> result = sigmaV1ConditionParser.parseRuleCondition(List.of(condition));
        assertTrue(result.test(matchingDataType));
        assertFalse(result.test(leftNonMatchingDataType));
        assertFalse(result.test(rightNonMatchingDataType));
        assertFalse(result.test(nonMatchingDataType));

        verify(sigmaV1LeafConditionParser).parseLeafCondition(eq(condition1));
        verify(sigmaV1LeafConditionParser).parseLeafCondition(eq(condition2));
    }

    @Test
    public void testParseRuleCondition_OrCondition() {
        final DataType matchingDataType = RuleEngineTestHelpers.getDataType(MATCHING_DATA_TYPE_FIELDS);
        final DataType leftOrMatchingDataType = RuleEngineTestHelpers.getDataType(Map.of(
                FIELD_NAME1, FIELD_VALUE1,
                FIELD_NAME2, UUID.randomUUID().toString()
        ));
        final DataType rightOrMatchingDataType = RuleEngineTestHelpers.getDataType(Map.of(
                FIELD_NAME1, UUID.randomUUID().toString(),
                FIELD_NAME2, FIELD_VALUE2
        ));
        final DataType nonMatchingDataType = RuleEngineTestHelpers.getDataType(NON_MATCHING_DATA_TYPE_FIELDS);

        final ConditionFieldEqualsValueExpression condition1 = new ConditionFieldEqualsValueExpression(FIELD_NAME1, new SigmaString(FIELD_VALUE1));
        final Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String> arg1 = Either.left(AnyOneOf.middleVal(condition1));
        final ConditionFieldEqualsValueExpression condition2 = new ConditionFieldEqualsValueExpression(FIELD_NAME2, new SigmaString(FIELD_VALUE2));
        final Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String> arg2 = Either.left(AnyOneOf.middleVal(condition2));
        final ConditionOR condition = new ConditionOR(false, List.of(arg1, arg2));

        when(sigmaV1LeafConditionParser.parseLeafCondition(eq(condition1))).thenReturn(x -> FIELD_VALUE1.equals(x.getValue(FIELD_NAME1)));
        when(sigmaV1LeafConditionParser.parseLeafCondition(eq(condition2))).thenReturn(x -> FIELD_VALUE2.equals(x.getValue(FIELD_NAME2)));

        final Predicate<DataType> result = sigmaV1ConditionParser.parseRuleCondition(List.of(condition));
        assertTrue(result.test(matchingDataType));
        assertTrue(result.test(leftOrMatchingDataType));
        assertTrue(result.test(rightOrMatchingDataType));
        assertFalse(result.test(nonMatchingDataType));

        verify(sigmaV1LeafConditionParser).parseLeafCondition(eq(condition1));
        verify(sigmaV1LeafConditionParser).parseLeafCondition(eq(condition2));
    }

    @Test
    public void testParseRuleCondition_NotCondition() {
        final DataType matchingDataType = RuleEngineTestHelpers.getDataType(NON_MATCHING_DATA_TYPE_FIELDS);
        final DataType nonMatchingDataType = RuleEngineTestHelpers.getDataType(MATCHING_DATA_TYPE_FIELDS);

        final ConditionFieldEqualsValueExpression condition1 = new ConditionFieldEqualsValueExpression(FIELD_NAME1, new SigmaString(FIELD_VALUE1));
        final Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String> arg1 = Either.left(AnyOneOf.middleVal(condition1));
        final ConditionNOT condition = new ConditionNOT(false, List.of(arg1));

        when(sigmaV1LeafConditionParser.parseLeafCondition(eq(condition1))).thenReturn(x -> FIELD_VALUE1.equals(x.getValue(FIELD_NAME1)));

        final Predicate<DataType> result = sigmaV1ConditionParser.parseRuleCondition(List.of(condition));
        assertTrue(result.test(matchingDataType));
        assertFalse(result.test(nonMatchingDataType));

        verify(sigmaV1LeafConditionParser).parseLeafCondition(eq(condition1));
    }

    @Test
    public void testParseRuleCondition_AndCondition_TooFewArgsThrowsRuleParseException() {
        final ConditionFieldEqualsValueExpression condition1 = new ConditionFieldEqualsValueExpression(FIELD_NAME1, new SigmaString(FIELD_VALUE1));
        final Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String> arg1 = Either.left(AnyOneOf.middleVal(condition1));
        final Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String> arg2 = Either.right(UUID.randomUUID().toString());
        final ConditionAND condition = new ConditionAND(false, List.of(arg1, arg2));

        assertThrows(RuleParseException.class, () -> sigmaV1ConditionParser.parseRuleCondition(List.of(condition)));

        verify(sigmaV1LeafConditionParser).parseLeafCondition(eq(condition1));
    }

    @Test
    public void testParseRuleCondition_OrCondition_TooFewArgsThrowsRuleParseException() {
        final ConditionFieldEqualsValueExpression condition1 = new ConditionFieldEqualsValueExpression(FIELD_NAME1, new SigmaString(FIELD_VALUE1));
        final Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String> arg1 = Either.left(AnyOneOf.middleVal(condition1));
        final Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String> arg2 = Either.right(UUID.randomUUID().toString());
        final ConditionOR condition = new ConditionOR(false, List.of(arg1, arg2));

        assertThrows(RuleParseException.class, () -> sigmaV1ConditionParser.parseRuleCondition(List.of(condition)));

        verify(sigmaV1LeafConditionParser).parseLeafCondition(eq(condition1));
    }

    @Test
    public void testParseRuleCondition_NotCondition_TooFewArgsThrowsRuleParseException() {
        final Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String> arg1 = Either.right(UUID.randomUUID().toString());
        final ConditionNOT condition = new ConditionNOT(false, List.of(arg1));

        assertThrows(RuleParseException.class, () -> sigmaV1ConditionParser.parseRuleCondition(List.of(condition)));
    }

    @Test
    public void testParseRuleCondition_NestedAndCondition() {
        final DataType matchingDataType = RuleEngineTestHelpers.getDataType(MATCHING_DATA_TYPE_FIELDS);
        final DataType nonMatchingDataType1 = RuleEngineTestHelpers.getDataType(NON_MATCHING_DATA_TYPE_FIELDS);
        final DataType nonMatchingDataType2 = RuleEngineTestHelpers.getDataType(Map.of(
                FIELD_NAME1, FIELD_VALUE1,
                FIELD_NAME2, FIELD_VALUE2,
                FIELD_NAME3, UUID.randomUUID().toString()
        ));
        final DataType nonMatchingDataType3 = RuleEngineTestHelpers.getDataType(Map.of(
                FIELD_NAME1, FIELD_VALUE1,
                FIELD_NAME2, UUID.randomUUID().toString(),
                FIELD_NAME3, FIELD_VALUE3
        ));
        final DataType nonMatchingDataType4 = RuleEngineTestHelpers.getDataType(Map.of(
                FIELD_NAME1, UUID.randomUUID().toString(),
                FIELD_NAME2, FIELD_VALUE2,
                FIELD_NAME3, FIELD_VALUE3
        ));
        final DataType nonMatchingDataType5 = RuleEngineTestHelpers.getDataType(Map.of(
                FIELD_NAME1, FIELD_VALUE1,
                FIELD_NAME2, UUID.randomUUID().toString(),
                FIELD_NAME3, UUID.randomUUID().toString()
        ));
        final DataType nonMatchingDataType6 = RuleEngineTestHelpers.getDataType(Map.of(
                FIELD_NAME1, UUID.randomUUID().toString(),
                FIELD_NAME2, FIELD_VALUE2,
                FIELD_NAME3, UUID.randomUUID().toString()
        ));
        final DataType nonMatchingDataType7 = RuleEngineTestHelpers.getDataType(Map.of(
                FIELD_NAME1, UUID.randomUUID().toString(),
                FIELD_NAME2, UUID.randomUUID().toString(),
                FIELD_NAME3, FIELD_VALUE3
        ));


        final ConditionFieldEqualsValueExpression condition1 = new ConditionFieldEqualsValueExpression(FIELD_NAME1, new SigmaString(FIELD_VALUE1));
        final Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String> arg1 = Either.left(AnyOneOf.middleVal(condition1));
        final ConditionFieldEqualsValueExpression condition2 = new ConditionFieldEqualsValueExpression(FIELD_NAME2, new SigmaString(FIELD_VALUE2));
        final Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String> arg2 = Either.left(AnyOneOf.middleVal(condition2));
        final ConditionFieldEqualsValueExpression condition3 = new ConditionFieldEqualsValueExpression(FIELD_NAME3, new SigmaString(FIELD_VALUE3));
        final Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String> arg3 = Either.left(AnyOneOf.middleVal(condition3));
        final ConditionAND nestedCondition = new ConditionAND(false, List.of(arg2, arg3));
        final Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String> nestedArg = Either.left(AnyOneOf.leftVal(nestedCondition));
        final ConditionAND condition = new ConditionAND(false, List.of(arg1, nestedArg));

        when(sigmaV1LeafConditionParser.parseLeafCondition(eq(condition1))).thenReturn(x -> FIELD_VALUE1.equals(x.getValue(FIELD_NAME1)));
        when(sigmaV1LeafConditionParser.parseLeafCondition(eq(condition2))).thenReturn(x -> FIELD_VALUE2.equals(x.getValue(FIELD_NAME2)));
        when(sigmaV1LeafConditionParser.parseLeafCondition(eq(condition3))).thenReturn(x -> FIELD_VALUE3.equals(x.getValue(FIELD_NAME3)));

        final Predicate<DataType> result = sigmaV1ConditionParser.parseRuleCondition(List.of(condition));
        assertTrue(result.test(matchingDataType));
        assertFalse(result.test(nonMatchingDataType1));
        assertFalse(result.test(nonMatchingDataType2));
        assertFalse(result.test(nonMatchingDataType3));
        assertFalse(result.test(nonMatchingDataType4));
        assertFalse(result.test(nonMatchingDataType5));
        assertFalse(result.test(nonMatchingDataType6));
        assertFalse(result.test(nonMatchingDataType7));

        verify(sigmaV1LeafConditionParser).parseLeafCondition(eq(condition1));
        verify(sigmaV1LeafConditionParser).parseLeafCondition(eq(condition2));
        verify(sigmaV1LeafConditionParser).parseLeafCondition(eq(condition3));
    }

    @Test
    public void testParseRuleCondition_NestedOrCondition() {
        final DataType matchingDataType1 = RuleEngineTestHelpers.getDataType(MATCHING_DATA_TYPE_FIELDS);
        final DataType matchingDataType2 = RuleEngineTestHelpers.getDataType(Map.of(
                FIELD_NAME1, FIELD_VALUE1,
                FIELD_NAME2, FIELD_VALUE2,
                FIELD_NAME3, UUID.randomUUID().toString()
        ));
        final DataType matchingDataType3 = RuleEngineTestHelpers.getDataType(Map.of(
                FIELD_NAME1, FIELD_VALUE1,
                FIELD_NAME2, UUID.randomUUID().toString(),
                FIELD_NAME3, FIELD_VALUE3
        ));
        final DataType matchingDataType4 = RuleEngineTestHelpers.getDataType(Map.of(
                FIELD_NAME1, UUID.randomUUID().toString(),
                FIELD_NAME2, FIELD_VALUE2,
                FIELD_NAME3, FIELD_VALUE3
        ));
        final DataType matchingDataType5 = RuleEngineTestHelpers.getDataType(Map.of(
                FIELD_NAME1, FIELD_VALUE1,
                FIELD_NAME2, UUID.randomUUID().toString(),
                FIELD_NAME3, UUID.randomUUID().toString()
        ));
        final DataType matchingDataType6 = RuleEngineTestHelpers.getDataType(Map.of(
                FIELD_NAME1, UUID.randomUUID().toString(),
                FIELD_NAME2, FIELD_VALUE2,
                FIELD_NAME3, UUID.randomUUID().toString()
        ));
        final DataType matchingDataType7 = RuleEngineTestHelpers.getDataType(Map.of(
                FIELD_NAME1, UUID.randomUUID().toString(),
                FIELD_NAME2, UUID.randomUUID().toString(),
                FIELD_NAME3, FIELD_VALUE3
        ));
        final DataType nonMatchingDataType = RuleEngineTestHelpers.getDataType(NON_MATCHING_DATA_TYPE_FIELDS);

        final ConditionFieldEqualsValueExpression condition1 = new ConditionFieldEqualsValueExpression(FIELD_NAME1, new SigmaString(FIELD_VALUE1));
        final Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String> arg1 = Either.left(AnyOneOf.middleVal(condition1));
        final ConditionFieldEqualsValueExpression condition2 = new ConditionFieldEqualsValueExpression(FIELD_NAME2, new SigmaString(FIELD_VALUE2));
        final Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String> arg2 = Either.left(AnyOneOf.middleVal(condition2));
        final ConditionFieldEqualsValueExpression condition3 = new ConditionFieldEqualsValueExpression(FIELD_NAME3, new SigmaString(FIELD_VALUE3));
        final Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String> arg3 = Either.left(AnyOneOf.middleVal(condition3));
        final ConditionOR nestedCondition = new ConditionOR(false, List.of(arg2, arg3));
        final Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String> nestedArg = Either.left(AnyOneOf.leftVal(nestedCondition));
        final ConditionOR condition = new ConditionOR(false, List.of(arg1, nestedArg));

        when(sigmaV1LeafConditionParser.parseLeafCondition(eq(condition1))).thenReturn(x -> FIELD_VALUE1.equals(x.getValue(FIELD_NAME1)));
        when(sigmaV1LeafConditionParser.parseLeafCondition(eq(condition2))).thenReturn(x -> FIELD_VALUE2.equals(x.getValue(FIELD_NAME2)));
        when(sigmaV1LeafConditionParser.parseLeafCondition(eq(condition3))).thenReturn(x -> FIELD_VALUE3.equals(x.getValue(FIELD_NAME3)));

        final Predicate<DataType> result = sigmaV1ConditionParser.parseRuleCondition(List.of(condition));
        assertTrue(result.test(matchingDataType1));
        assertTrue(result.test(matchingDataType2));
        assertTrue(result.test(matchingDataType3));
        assertTrue(result.test(matchingDataType4));
        assertTrue(result.test(matchingDataType5));
        assertTrue(result.test(matchingDataType6));
        assertTrue(result.test(matchingDataType7));
        assertFalse(result.test(nonMatchingDataType));

        verify(sigmaV1LeafConditionParser).parseLeafCondition(eq(condition1));
        verify(sigmaV1LeafConditionParser).parseLeafCondition(eq(condition2));
        verify(sigmaV1LeafConditionParser).parseLeafCondition(eq(condition3));
    }

    @Test
    public void testParseRuleCondition_CombinationNestedCondition() {
        final DataType matchingDataType1 = RuleEngineTestHelpers.getDataType(Map.of(
                FIELD_NAME1, FIELD_VALUE1,
                FIELD_NAME2, FIELD_VALUE2,
                FIELD_NAME3, UUID.randomUUID().toString()
        ));
        final DataType matchingDataType2 = RuleEngineTestHelpers.getDataType(Map.of(
                FIELD_NAME1, FIELD_VALUE1,
                FIELD_NAME2, UUID.randomUUID().toString(),
                FIELD_NAME3, UUID.randomUUID().toString()
        ));
        final DataType matchingDataType3 = RuleEngineTestHelpers.getDataType(MATCHING_DATA_TYPE_FIELDS);
        final DataType nonMatchingDataType1 = RuleEngineTestHelpers.getDataType(Map.of(
                FIELD_NAME1, FIELD_VALUE1,
                FIELD_NAME2, UUID.randomUUID().toString(),
                FIELD_NAME3, FIELD_VALUE3
        ));
        final DataType nonMatchingDataType2 = RuleEngineTestHelpers.getDataType(Map.of(
                FIELD_NAME1, UUID.randomUUID().toString(),
                FIELD_NAME2, FIELD_VALUE2,
                FIELD_NAME3, FIELD_VALUE3
        ));
        final DataType nonMatchingDataType3 = RuleEngineTestHelpers.getDataType(Map.of(
                FIELD_NAME1, UUID.randomUUID().toString(),
                FIELD_NAME2, FIELD_VALUE2,
                FIELD_NAME3, UUID.randomUUID().toString()
        ));
        final DataType nonMatchingDataType4 = RuleEngineTestHelpers.getDataType(Map.of(
                FIELD_NAME1, UUID.randomUUID().toString(),
                FIELD_NAME2, UUID.randomUUID().toString(),
                FIELD_NAME3, FIELD_VALUE3
        ));
        final DataType nonMatchingDataType5 = RuleEngineTestHelpers.getDataType(NON_MATCHING_DATA_TYPE_FIELDS);

        final ConditionFieldEqualsValueExpression condition1 = new ConditionFieldEqualsValueExpression(FIELD_NAME1, new SigmaString(FIELD_VALUE1));
        final Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String> arg1 = Either.left(AnyOneOf.middleVal(condition1));
        final ConditionFieldEqualsValueExpression condition2 = new ConditionFieldEqualsValueExpression(FIELD_NAME2, new SigmaString(FIELD_VALUE2));
        final Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String> arg2 = Either.left(AnyOneOf.middleVal(condition2));
        final ConditionFieldEqualsValueExpression condition3 = new ConditionFieldEqualsValueExpression(FIELD_NAME3, new SigmaString(FIELD_VALUE3));
        final Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String> arg3 = Either.left(AnyOneOf.middleVal(condition3));
        final ConditionNOT notCondition = new ConditionNOT(false, List.of(arg3));
        final Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String> notArg = Either.left(AnyOneOf.leftVal(notCondition));
        final ConditionOR nestedCondition = new ConditionOR(false, List.of(arg2, notArg));
        final Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String> nestedArg = Either.left(AnyOneOf.leftVal(nestedCondition));
        final ConditionAND condition = new ConditionAND(false, List.of(arg1, nestedArg));

        when(sigmaV1LeafConditionParser.parseLeafCondition(eq(condition1))).thenReturn(x -> FIELD_VALUE1.equals(x.getValue(FIELD_NAME1)));
        when(sigmaV1LeafConditionParser.parseLeafCondition(eq(condition2))).thenReturn(x -> FIELD_VALUE2.equals(x.getValue(FIELD_NAME2)));
        when(sigmaV1LeafConditionParser.parseLeafCondition(eq(condition3))).thenReturn(x -> FIELD_VALUE3.equals(x.getValue(FIELD_NAME3)));

        final Predicate<DataType> result = sigmaV1ConditionParser.parseRuleCondition(List.of(condition));
        assertTrue(result.test(matchingDataType1));
        assertTrue(result.test(matchingDataType2));
        assertTrue(result.test(matchingDataType3));
        assertFalse(result.test(nonMatchingDataType1));
        assertFalse(result.test(nonMatchingDataType2));
        assertFalse(result.test(nonMatchingDataType3));
        assertFalse(result.test(nonMatchingDataType4));
        assertFalse(result.test(nonMatchingDataType5));

        verify(sigmaV1LeafConditionParser).parseLeafCondition(eq(condition1));
        verify(sigmaV1LeafConditionParser).parseLeafCondition(eq(condition2));
        verify(sigmaV1LeafConditionParser).parseLeafCondition(eq(condition3));
    }

    @Test
    public void testParseRuleCondition_MultipleConditionsLogicallyORed() {
        final DataType matchingDataType = RuleEngineTestHelpers.getDataType(MATCHING_DATA_TYPE_FIELDS);
        final DataType leftOrMatchingDataType = RuleEngineTestHelpers.getDataType(Map.of(
                FIELD_NAME1, FIELD_VALUE1,
                FIELD_NAME2, UUID.randomUUID().toString()
        ));
        final DataType rightOrMatchingDataType = RuleEngineTestHelpers.getDataType(Map.of(
                FIELD_NAME1, UUID.randomUUID().toString(),
                FIELD_NAME2, FIELD_VALUE2
        ));
        final DataType nonMatchingDataType = RuleEngineTestHelpers.getDataType(NON_MATCHING_DATA_TYPE_FIELDS);

        final ConditionFieldEqualsValueExpression condition1 = new ConditionFieldEqualsValueExpression(FIELD_NAME1, new SigmaString(FIELD_VALUE1));
        final ConditionFieldEqualsValueExpression condition2 = new ConditionFieldEqualsValueExpression(FIELD_NAME2, new SigmaString(FIELD_VALUE2));

        when(sigmaV1LeafConditionParser.parseLeafCondition(eq(condition1))).thenReturn(x -> FIELD_VALUE1.equals(x.getValue(FIELD_NAME1)));
        when(sigmaV1LeafConditionParser.parseLeafCondition(eq(condition2))).thenReturn(x -> FIELD_VALUE2.equals(x.getValue(FIELD_NAME2)));

        final Predicate<DataType> result = sigmaV1ConditionParser.parseRuleCondition(List.of(condition1, condition2));
        assertTrue(result.test(matchingDataType));
        assertTrue(result.test(leftOrMatchingDataType));
        assertTrue(result.test(rightOrMatchingDataType));
        assertFalse(result.test(nonMatchingDataType));

        verify(sigmaV1LeafConditionParser).parseLeafCondition(eq(condition1));
        verify(sigmaV1LeafConditionParser).parseLeafCondition(eq(condition2));
    }

    @Test
    public void testParseRuleCondition_NoConditionsReturnsAlwaysFalse() {
        final DataType matchingDataType = RuleEngineTestHelpers.getDataType(MATCHING_DATA_TYPE_FIELDS);
        final DataType nonMatchingDataType = RuleEngineTestHelpers.getDataType(NON_MATCHING_DATA_TYPE_FIELDS);

        final Predicate<DataType> result = sigmaV1ConditionParser.parseRuleCondition(Collections.emptyList());
        assertFalse(result.test(null));
        assertFalse(result.test(matchingDataType));
        assertFalse(result.test(nonMatchingDataType));
    }
}
