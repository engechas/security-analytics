/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.ruleengine.field;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensearch.securityanalytics.ruleengine.RuleEngineTestHelpers;
import org.opensearch.securityanalytics.ruleengine.exception.RuleEvaluationException;
import org.opensearch.securityanalytics.ruleengine.model.DataType;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class FieldAccessorTests {
    private static final Random RANDOM = new Random();
    private static final String STRING_VALUE_1 = UUID.randomUUID().toString();
    private static final String STRING_VALUE_2 = UUID.randomUUID().toString();
    private static final Integer INTEGER_VALUE_1 = RANDOM.nextInt();
    private static final Integer INTEGER_VALUE_2 = RANDOM.nextInt();
    private static final Float FLOAT_VALUE_1 = RANDOM.nextFloat();
    private static final Float FLOAT_VALUE_2 = RANDOM.nextFloat();
    private static final Double DOUBLE_VALUE_1 = RANDOM.nextDouble();
    private static final Double DOUBLE_VALUE_2 = RANDOM.nextDouble();

    private static final Map<String, String> FIELD_TRANSLATIONS = Map.of(
            "field1", "translatedField1",
            "field2", "translatedField2",
            "field3", "translatedField3",
            "field4", "translatedField4",
            "field5", "translatedField5",
            "field6", "translatedField6"
    );
    private static final Map<String, Object> FIELDS = getFieldsMap();
    private static final DataType DATA_TYPE = new RuleEngineTestHelpers.MapDataType(FIELDS);

    private FieldAccessor fieldAccessorWithTranslations;
    private FieldAccessor fieldAccessorWithoutTranslations;

    @BeforeEach
    public void setup() {
        this.fieldAccessorWithTranslations = new FieldAccessor(FIELD_TRANSLATIONS);
        this.fieldAccessorWithoutTranslations = new FieldAccessor(null);
    }

    @Test
    public void testGetStringValue_WithTranslation() {
        final String result = fieldAccessorWithTranslations.getStringValue(DATA_TYPE, "field1");
        assertEquals(STRING_VALUE_2, result);
    }

    @Test
    public void testGetStringValue_WithoutTranslation() {
        final String result = fieldAccessorWithoutTranslations.getStringValue(DATA_TYPE, "field1");
        assertEquals(STRING_VALUE_1, result);
    }

    @Test
    public void testGetBooleanValue_WithTranslation() {
        final Boolean result = fieldAccessorWithTranslations.getBooleanValue(DATA_TYPE, "field2");
        assertEquals(Boolean.FALSE, result);
    }

    @Test
    public void testGetBooleanValue_WithoutTranslation() {
        final Boolean result = fieldAccessorWithoutTranslations.getBooleanValue(DATA_TYPE, "field2");
        assertEquals(Boolean.TRUE, result);
    }

    @Test
    public void testGetIntegerValue_WithTranslation() {
        final Integer result = fieldAccessorWithTranslations.getIntegerValue(DATA_TYPE, "field3");
        assertEquals(INTEGER_VALUE_2, result);
    }

    @Test
    public void testGetIntegerValue_WithoutTranslation() {
        final Integer result = fieldAccessorWithoutTranslations.getIntegerValue(DATA_TYPE, "field3");
        assertEquals(INTEGER_VALUE_1, result);
    }

    @Test
    public void testGetFloatValue_WithTranslation() {
        final Float result = fieldAccessorWithTranslations.getFloatValue(DATA_TYPE, "field4");
        assertEquals(FLOAT_VALUE_2, result);
    }

    @Test
    public void testGetFloatValue_WithoutTranslation() {
        final Float result = fieldAccessorWithoutTranslations.getFloatValue(DATA_TYPE, "field4");
        assertEquals(FLOAT_VALUE_1, result);
    }

    @Test
    public void testGetDoubleValue_WithTranslation() {
        final Double result = fieldAccessorWithTranslations.getDoubleValue(DATA_TYPE, "field5");
        assertEquals(DOUBLE_VALUE_2, result);
    }

    @Test
    public void testGetDoubleValue_WithoutTranslation() {
        final Double result = fieldAccessorWithoutTranslations.getDoubleValue(DATA_TYPE, "field5");
        assertEquals(DOUBLE_VALUE_1, result);
    }

    @Test
    public void testGetObjectValue_WithTranslation() {
        final Object result = fieldAccessorWithTranslations.getObjectValue(DATA_TYPE, "field6");
        assertEquals(Collections.emptyMap(), result);
    }

    @Test
    public void testGetObjectValue_WithoutTranslation() {
        final Object result = fieldAccessorWithoutTranslations.getObjectValue(DATA_TYPE, "field6");
        assertEquals(Collections.emptyList(), result);
    }

    @Test
    public void testGetValue_ClassCastException_ThrowsRuleEvaluationException() {
        assertThrows(RuleEvaluationException.class, () -> fieldAccessorWithoutTranslations.getDoubleValue(DATA_TYPE, "field3"));
    }

    @Test
    public void testGetValue_FieldDoesntExist_ReturnsNull() {
        final String stringResult = fieldAccessorWithoutTranslations.getStringValue(DATA_TYPE, UUID.randomUUID().toString());
        final Boolean booleanResult = fieldAccessorWithoutTranslations.getBooleanValue(DATA_TYPE, UUID.randomUUID().toString());
        final Float floatResult = fieldAccessorWithoutTranslations.getFloatValue(DATA_TYPE, UUID.randomUUID().toString());
        final Integer integerResult = fieldAccessorWithoutTranslations.getIntegerValue(DATA_TYPE, UUID.randomUUID().toString());
        final Double doubleResult = fieldAccessorWithoutTranslations.getDoubleValue(DATA_TYPE, UUID.randomUUID().toString());
        final Object objectResult = fieldAccessorWithoutTranslations.getObjectValue(DATA_TYPE, UUID.randomUUID().toString());

        assertNull(stringResult);
        assertNull(booleanResult);
        assertNull(floatResult);
        assertNull(integerResult);
        assertNull(doubleResult);
        assertNull(objectResult);
    }

    private static Map<String, Object> getFieldsMap() {
        final HashMap<String, Object> fieldsMap = new HashMap<>();
        fieldsMap.put("field1", STRING_VALUE_1);
        fieldsMap.put("translatedField1", STRING_VALUE_2);
        fieldsMap.put("field2", Boolean.TRUE);
        fieldsMap.put("translatedField2", Boolean.FALSE);
        fieldsMap.put("field3", INTEGER_VALUE_1);
        fieldsMap.put("translatedField3", INTEGER_VALUE_2);
        fieldsMap.put("field4", FLOAT_VALUE_1);
        fieldsMap.put("translatedField4", FLOAT_VALUE_2);
        fieldsMap.put("field5", DOUBLE_VALUE_1);
        fieldsMap.put("translatedField5", DOUBLE_VALUE_2);
        fieldsMap.put("field6", Collections.emptyList());
        fieldsMap.put("translatedField6", Collections.emptyMap());

        return fieldsMap;
    }
}
