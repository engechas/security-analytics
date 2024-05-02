package org.opensearch.securityanalytics.ruleengine.parser.sigma.v1;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.opensearch.securityanalytics.ruleengine.RuleEngineTestHelpers;
import org.opensearch.securityanalytics.ruleengine.field.FieldAccessor;
import org.opensearch.securityanalytics.ruleengine.model.DataType;
import org.opensearch.securityanalytics.rules.condition.ConditionFieldEqualsValueExpression;
import org.opensearch.securityanalytics.rules.exceptions.SigmaRegularExpressionError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaTypeError;
import org.opensearch.securityanalytics.rules.types.SigmaBool;
import org.opensearch.securityanalytics.rules.types.SigmaCIDRExpression;
import org.opensearch.securityanalytics.rules.types.SigmaCompareExpression;
import org.opensearch.securityanalytics.rules.types.SigmaNull;
import org.opensearch.securityanalytics.rules.types.SigmaNumber;
import org.opensearch.securityanalytics.rules.types.SigmaRegularExpression;
import org.opensearch.securityanalytics.rules.types.SigmaString;

import java.util.Collections;
import java.util.Map;
import java.util.Random;
import java.util.UUID;
import java.util.function.Predicate;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

public class SigmaV1LeafConditionParserTests {
    private static final Random RANDOM = new Random();
    private static final String FIELD_NAME = UUID.randomUUID().toString();

    @Mock
    private FieldAccessor fieldAccessor;

    private SigmaV1LeafConditionParser parser;

    @BeforeEach
    public void setup() {
        MockitoAnnotations.openMocks(this);
        parser = new SigmaV1LeafConditionParser(fieldAccessor);
    }

    @AfterEach
    public void afterTest() {
        verifyNoMoreInteractions(fieldAccessor);
    }

    @Test
    public void testStringEquals() {
        final String fieldValue = UUID.randomUUID().toString();
        final String otherFieldValue = UUID.randomUUID().toString();

        final DataType matchingDataType = RuleEngineTestHelpers.getDataType(Map.of(FIELD_NAME, fieldValue));
        final DataType nonMatchingDataType = RuleEngineTestHelpers.getDataType(Map.of(FIELD_NAME, otherFieldValue));

        when(fieldAccessor.getStringValue(eq(matchingDataType), eq(FIELD_NAME))).thenReturn(fieldValue);
        when(fieldAccessor.getStringValue(eq(nonMatchingDataType), eq(FIELD_NAME))).thenReturn(otherFieldValue);

        final ConditionFieldEqualsValueExpression condition = new ConditionFieldEqualsValueExpression(FIELD_NAME, new SigmaString(fieldValue));
        final Predicate<DataType> result = parser.parseLeafCondition(condition);

        assertTrue(result.test(matchingDataType));
        assertFalse(result.test(nonMatchingDataType));

        verify(fieldAccessor).getStringValue(eq(matchingDataType), eq(FIELD_NAME));
        verify(fieldAccessor).getStringValue(eq(nonMatchingDataType), eq(FIELD_NAME));
    }

    @Test
    public void testStringEquals_nullDoesNotMatch_DoesNotThrow() {
        final DataType matchingDataType = RuleEngineTestHelpers.getDataType(Collections.emptyMap());
        when(fieldAccessor.getStringValue(eq(matchingDataType), eq(FIELD_NAME))).thenReturn(null);

        final ConditionFieldEqualsValueExpression condition = new ConditionFieldEqualsValueExpression(FIELD_NAME, new SigmaString(""));
        final Predicate<DataType> result = parser.parseLeafCondition(condition);

        assertFalse(result.test(matchingDataType));
        verify(fieldAccessor).getStringValue(eq(matchingDataType), eq(FIELD_NAME));
    }

    @Test
    public void testBooleanEquals() {
        final Boolean fieldValue = Boolean.TRUE;
        final Boolean otherFieldValue = Boolean.FALSE;

        final DataType matchingDataType = RuleEngineTestHelpers.getDataType(Map.of(FIELD_NAME, fieldValue));
        final DataType nonMatchingDataType = RuleEngineTestHelpers.getDataType(Map.of(FIELD_NAME, otherFieldValue));

        when(fieldAccessor.getBooleanValue(eq(matchingDataType), eq(FIELD_NAME))).thenReturn(fieldValue);
        when(fieldAccessor.getBooleanValue(eq(nonMatchingDataType), eq(FIELD_NAME))).thenReturn(otherFieldValue);

        final ConditionFieldEqualsValueExpression condition = new ConditionFieldEqualsValueExpression(FIELD_NAME, new SigmaBool(fieldValue));
        final Predicate<DataType> result = parser.parseLeafCondition(condition);

        assertTrue(result.test(matchingDataType));
        assertFalse(result.test(nonMatchingDataType));

        verify(fieldAccessor).getBooleanValue(eq(matchingDataType), eq(FIELD_NAME));
        verify(fieldAccessor).getBooleanValue(eq(nonMatchingDataType), eq(FIELD_NAME));
    }

    @Test
    public void testBooleanEquals_nullDoesNotMatch_DoesNotThrow() {
        final DataType matchingDataType = RuleEngineTestHelpers.getDataType(Collections.emptyMap());
        when(fieldAccessor.getBooleanValue(eq(matchingDataType), eq(FIELD_NAME))).thenReturn(null);

        final ConditionFieldEqualsValueExpression condition = new ConditionFieldEqualsValueExpression(FIELD_NAME, new SigmaBool(Boolean.FALSE));
        final Predicate<DataType> result = parser.parseLeafCondition(condition);

        assertFalse(result.test(matchingDataType));
        verify(fieldAccessor).getBooleanValue(eq(matchingDataType), eq(FIELD_NAME));
    }

    @Test
    public void testFloatEquals() {
        final Float fieldValue = RANDOM.nextFloat();
        final Float otherFieldValue = RANDOM.nextFloat();

        final DataType matchingDataType = RuleEngineTestHelpers.getDataType(Map.of(FIELD_NAME, fieldValue));
        final DataType nonMatchingDataType = RuleEngineTestHelpers.getDataType(Map.of(FIELD_NAME, otherFieldValue));

        when(fieldAccessor.getFloatValue(eq(matchingDataType), eq(FIELD_NAME))).thenReturn(fieldValue);
        when(fieldAccessor.getFloatValue(eq(nonMatchingDataType), eq(FIELD_NAME))).thenReturn(otherFieldValue);

        final ConditionFieldEqualsValueExpression condition = new ConditionFieldEqualsValueExpression(FIELD_NAME, new SigmaNumber(fieldValue));
        final Predicate<DataType> result = parser.parseLeafCondition(condition);

        assertTrue(result.test(matchingDataType));
        assertFalse(result.test(nonMatchingDataType));

        verify(fieldAccessor).getFloatValue(eq(matchingDataType), eq(FIELD_NAME));
        verify(fieldAccessor).getFloatValue(eq(nonMatchingDataType), eq(FIELD_NAME));
    }

    @Test
    public void testFloatEquals_nullDoesNotMatch_DoesNotThrow() {
        final DataType matchingDataType = RuleEngineTestHelpers.getDataType(Collections.emptyMap());
        when(fieldAccessor.getFloatValue(eq(matchingDataType), eq(FIELD_NAME))).thenReturn(null);

        final ConditionFieldEqualsValueExpression condition = new ConditionFieldEqualsValueExpression(FIELD_NAME, new SigmaNumber(0f));
        final Predicate<DataType> result = parser.parseLeafCondition(condition);

        assertFalse(result.test(matchingDataType));
        verify(fieldAccessor).getFloatValue(eq(matchingDataType), eq(FIELD_NAME));
    }

    @Test
    public void testIntegerEquals() {
        final Integer fieldValue = RANDOM.nextInt();
        final Integer otherFieldValue = RANDOM.nextInt();

        final DataType matchingDataType = RuleEngineTestHelpers.getDataType(Map.of(FIELD_NAME, fieldValue));
        final DataType nonMatchingDataType = RuleEngineTestHelpers.getDataType(Map.of(FIELD_NAME, otherFieldValue));

        when(fieldAccessor.getIntegerValue(eq(matchingDataType), eq(FIELD_NAME))).thenReturn(fieldValue);
        when(fieldAccessor.getIntegerValue(eq(nonMatchingDataType), eq(FIELD_NAME))).thenReturn(otherFieldValue);

        final ConditionFieldEqualsValueExpression condition = new ConditionFieldEqualsValueExpression(FIELD_NAME, new SigmaNumber(fieldValue));
        final Predicate<DataType> result = parser.parseLeafCondition(condition);

        assertTrue(result.test(matchingDataType));
        assertFalse(result.test(nonMatchingDataType));

        verify(fieldAccessor).getIntegerValue(eq(matchingDataType), eq(FIELD_NAME));
        verify(fieldAccessor).getIntegerValue(eq(nonMatchingDataType), eq(FIELD_NAME));
    }

    @Test
    public void testIntegerEquals_nullDoesNotMatch_DoesNotThrow() {
        final DataType matchingDataType = RuleEngineTestHelpers.getDataType(Collections.emptyMap());
        when(fieldAccessor.getIntegerValue(eq(matchingDataType), eq(FIELD_NAME))).thenReturn(null);

        final ConditionFieldEqualsValueExpression condition = new ConditionFieldEqualsValueExpression(FIELD_NAME, new SigmaNumber(0));
        final Predicate<DataType> result = parser.parseLeafCondition(condition);

        assertFalse(result.test(matchingDataType));
        verify(fieldAccessor).getIntegerValue(eq(matchingDataType), eq(FIELD_NAME));
    }

    @Test
    public void testNullEquals() {
        final Object otherFieldValue = new Object();

        final DataType matchingDataType = RuleEngineTestHelpers.getDataType(Collections.emptyMap());
        final DataType nonMatchingDataType = RuleEngineTestHelpers.getDataType(Map.of(FIELD_NAME, otherFieldValue));

        when(fieldAccessor.getObjectValue(eq(matchingDataType), eq(FIELD_NAME))).thenReturn(null);
        when(fieldAccessor.getObjectValue(eq(nonMatchingDataType), eq(FIELD_NAME))).thenReturn(otherFieldValue);

        final ConditionFieldEqualsValueExpression condition = new ConditionFieldEqualsValueExpression(FIELD_NAME, new SigmaNull());
        final Predicate<DataType> result = parser.parseLeafCondition(condition);

        assertTrue(result.test(matchingDataType));
        assertFalse(result.test(nonMatchingDataType));

        verify(fieldAccessor).getObjectValue(eq(matchingDataType), eq(FIELD_NAME));
        verify(fieldAccessor).getObjectValue(eq(nonMatchingDataType), eq(FIELD_NAME));
    }

    @Test
    public void testRegExpEquals() throws SigmaRegularExpressionError {
        final String fieldValue = "aaa";
        final String otherFieldValue = "bbb";

        final DataType matchingDataType = RuleEngineTestHelpers.getDataType(Map.of(FIELD_NAME, fieldValue));
        final DataType nonMatchingDataType = RuleEngineTestHelpers.getDataType(Map.of(FIELD_NAME, otherFieldValue));

        when(fieldAccessor.getStringValue(eq(matchingDataType), eq(FIELD_NAME))).thenReturn(fieldValue);
        when(fieldAccessor.getStringValue(eq(nonMatchingDataType), eq(FIELD_NAME))).thenReturn(otherFieldValue);

        final ConditionFieldEqualsValueExpression condition = new ConditionFieldEqualsValueExpression(FIELD_NAME, new SigmaRegularExpression("a+"));
        final Predicate<DataType> result = parser.parseLeafCondition(condition);

        assertTrue(result.test(matchingDataType));
        assertFalse(result.test(nonMatchingDataType));

        verify(fieldAccessor).getStringValue(eq(matchingDataType), eq(FIELD_NAME));
        verify(fieldAccessor).getStringValue(eq(nonMatchingDataType), eq(FIELD_NAME));
    }

    @Test
    public void testRegExpEquals_nullDoesNotMatch_DoesNotThrow() throws SigmaRegularExpressionError {
        final DataType matchingDataType = RuleEngineTestHelpers.getDataType(Collections.emptyMap());
        when(fieldAccessor.getStringValue(eq(matchingDataType), eq(FIELD_NAME))).thenReturn(null);

        final ConditionFieldEqualsValueExpression condition = new ConditionFieldEqualsValueExpression(FIELD_NAME, new SigmaRegularExpression("."));
        final Predicate<DataType> result = parser.parseLeafCondition(condition);

        assertFalse(result.test(matchingDataType));
        verify(fieldAccessor).getStringValue(eq(matchingDataType), eq(FIELD_NAME));
    }

    @Test
    public void testCIDRContains() throws SigmaTypeError {
        final String fieldValue = "10.0.0.0";
        final String otherFieldValue = "10.0.1.0";

        final DataType matchingDataType = RuleEngineTestHelpers.getDataType(Map.of(FIELD_NAME, fieldValue));
        final DataType nonMatchingDataType = RuleEngineTestHelpers.getDataType(Map.of(FIELD_NAME, otherFieldValue));

        when(fieldAccessor.getStringValue(eq(matchingDataType), eq(FIELD_NAME))).thenReturn(fieldValue);
        when(fieldAccessor.getStringValue(eq(nonMatchingDataType), eq(FIELD_NAME))).thenReturn(otherFieldValue);

        final ConditionFieldEqualsValueExpression condition = new ConditionFieldEqualsValueExpression(FIELD_NAME, new SigmaCIDRExpression("10.0.0.0/24"));
        final Predicate<DataType> result = parser.parseLeafCondition(condition);

        assertTrue(result.test(matchingDataType));
        assertFalse(result.test(nonMatchingDataType));

        verify(fieldAccessor).getStringValue(eq(matchingDataType), eq(FIELD_NAME));
        verify(fieldAccessor).getStringValue(eq(nonMatchingDataType), eq(FIELD_NAME));
    }

    @Test
    public void testCIDRContains_nullDoesNotMatch_DoesNotThrow() throws SigmaTypeError {
        final DataType matchingDataType = RuleEngineTestHelpers.getDataType(Collections.emptyMap());
        when(fieldAccessor.getStringValue(eq(matchingDataType), eq(FIELD_NAME))).thenReturn(null);

        final ConditionFieldEqualsValueExpression condition = new ConditionFieldEqualsValueExpression(FIELD_NAME, new SigmaCIDRExpression("0.0.0.0/0"));
        final Predicate<DataType> result = parser.parseLeafCondition(condition);

        assertFalse(result.test(matchingDataType));
        verify(fieldAccessor).getStringValue(eq(matchingDataType), eq(FIELD_NAME));
    }

    @Test
    public void testGreaterThanCompare() {
        final Float fieldValue = RANDOM.nextFloat();
        final Float otherFieldValue = fieldValue - 2;

        final DataType matchingDataType = RuleEngineTestHelpers.getDataType(Map.of(FIELD_NAME, fieldValue));
        final DataType nonMatchingDataType = RuleEngineTestHelpers.getDataType(Map.of(FIELD_NAME, otherFieldValue));

        when(fieldAccessor.getFloatValue(eq(matchingDataType), eq(FIELD_NAME))).thenReturn(fieldValue);
        when(fieldAccessor.getFloatValue(eq(nonMatchingDataType), eq(FIELD_NAME))).thenReturn(otherFieldValue);

        final SigmaCompareExpression sigmaCompareExpression = new SigmaCompareExpression(new SigmaNumber(fieldValue - 1), SigmaCompareExpression.CompareOperators.GT);
        final ConditionFieldEqualsValueExpression condition = new ConditionFieldEqualsValueExpression(FIELD_NAME, sigmaCompareExpression);
        final Predicate<DataType> result = parser.parseLeafCondition(condition);

        assertTrue(result.test(matchingDataType));
        assertFalse(result.test(nonMatchingDataType));

        verify(fieldAccessor).getFloatValue(eq(matchingDataType), eq(FIELD_NAME));
        verify(fieldAccessor).getFloatValue(eq(nonMatchingDataType), eq(FIELD_NAME));
    }

    @Test
    public void testLessThanCompare() {
        final Float fieldValue = RANDOM.nextFloat();
        final Float otherFieldValue = fieldValue + 2;

        final DataType matchingDataType = RuleEngineTestHelpers.getDataType(Map.of(FIELD_NAME, fieldValue));
        final DataType nonMatchingDataType = RuleEngineTestHelpers.getDataType(Map.of(FIELD_NAME, otherFieldValue));

        when(fieldAccessor.getFloatValue(eq(matchingDataType), eq(FIELD_NAME))).thenReturn(fieldValue);
        when(fieldAccessor.getFloatValue(eq(nonMatchingDataType), eq(FIELD_NAME))).thenReturn(otherFieldValue);

        final SigmaCompareExpression sigmaCompareExpression = new SigmaCompareExpression(new SigmaNumber(fieldValue + 1), SigmaCompareExpression.CompareOperators.LT);
        final ConditionFieldEqualsValueExpression condition = new ConditionFieldEqualsValueExpression(FIELD_NAME, sigmaCompareExpression);
        final Predicate<DataType> result = parser.parseLeafCondition(condition);

        assertTrue(result.test(matchingDataType));
        assertFalse(result.test(nonMatchingDataType));

        verify(fieldAccessor).getFloatValue(eq(matchingDataType), eq(FIELD_NAME));
        verify(fieldAccessor).getFloatValue(eq(nonMatchingDataType), eq(FIELD_NAME));
    }

    @Test
    public void testGreaterThanOrEqualToCompare() {
        final Float fieldValue = RANDOM.nextFloat();
        final Float otherFieldValue = fieldValue - 1;

        final DataType matchingDataType = RuleEngineTestHelpers.getDataType(Map.of(FIELD_NAME, fieldValue));
        final DataType nonMatchingDataType = RuleEngineTestHelpers.getDataType(Map.of(FIELD_NAME, otherFieldValue));

        when(fieldAccessor.getFloatValue(eq(matchingDataType), eq(FIELD_NAME))).thenReturn(fieldValue);
        when(fieldAccessor.getFloatValue(eq(nonMatchingDataType), eq(FIELD_NAME))).thenReturn(otherFieldValue);

        final SigmaCompareExpression sigmaCompareExpression = new SigmaCompareExpression(new SigmaNumber(fieldValue), SigmaCompareExpression.CompareOperators.GTE);
        final ConditionFieldEqualsValueExpression condition = new ConditionFieldEqualsValueExpression(FIELD_NAME, sigmaCompareExpression);
        final Predicate<DataType> result = parser.parseLeafCondition(condition);

        assertTrue(result.test(matchingDataType));
        assertFalse(result.test(nonMatchingDataType));

        verify(fieldAccessor).getFloatValue(eq(matchingDataType), eq(FIELD_NAME));
        verify(fieldAccessor).getFloatValue(eq(nonMatchingDataType), eq(FIELD_NAME));
    }

    @Test
    public void testLessThanOrEqualToCompare() {
        final Float fieldValue = RANDOM.nextFloat();
        final Float otherFieldValue = fieldValue + 1;

        final DataType matchingDataType = RuleEngineTestHelpers.getDataType(Map.of(FIELD_NAME, fieldValue));
        final DataType nonMatchingDataType = RuleEngineTestHelpers.getDataType(Map.of(FIELD_NAME, otherFieldValue));

        when(fieldAccessor.getFloatValue(eq(matchingDataType), eq(FIELD_NAME))).thenReturn(fieldValue);
        when(fieldAccessor.getFloatValue(eq(nonMatchingDataType), eq(FIELD_NAME))).thenReturn(otherFieldValue);

        final SigmaCompareExpression sigmaCompareExpression = new SigmaCompareExpression(new SigmaNumber(fieldValue), SigmaCompareExpression.CompareOperators.LTE);
        final ConditionFieldEqualsValueExpression condition = new ConditionFieldEqualsValueExpression(FIELD_NAME, sigmaCompareExpression);
        final Predicate<DataType> result = parser.parseLeafCondition(condition);

        assertTrue(result.test(matchingDataType));
        assertFalse(result.test(nonMatchingDataType));

        verify(fieldAccessor).getFloatValue(eq(matchingDataType), eq(FIELD_NAME));
        verify(fieldAccessor).getFloatValue(eq(nonMatchingDataType), eq(FIELD_NAME));
    }

    @Test
    public void testNumericCompare_nullDoesNotMatch_DoesNotThrow() {
        final DataType matchingDataType = RuleEngineTestHelpers.getDataType(Collections.emptyMap());
        when(fieldAccessor.getFloatValue(eq(matchingDataType), eq(FIELD_NAME))).thenReturn(null);

        final SigmaCompareExpression sigmaCompareExpression = new SigmaCompareExpression(new SigmaNumber(0f), SigmaCompareExpression.CompareOperators.LTE);
        final ConditionFieldEqualsValueExpression condition = new ConditionFieldEqualsValueExpression(FIELD_NAME, sigmaCompareExpression);
        final Predicate<DataType> result = parser.parseLeafCondition(condition);

        assertFalse(result.test(matchingDataType));
        verify(fieldAccessor).getFloatValue(eq(matchingDataType), eq(FIELD_NAME));
    }
}
