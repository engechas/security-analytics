/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.ruleengine.field;

import org.opensearch.securityanalytics.ruleengine.exception.RuleEvaluationException;
import org.opensearch.securityanalytics.ruleengine.model.DataType;

import java.util.Collections;
import java.util.Map;

public class FieldAccessor {
    private final Map<String, String> fieldTranslations;

    public FieldAccessor(final Map<String, String> fieldTranslations) {
        this.fieldTranslations = fieldTranslations == null ? Collections.emptyMap() : fieldTranslations;
    }

    public String getStringValue(final DataType dataType, final String fieldName) {
        return getValue(dataType, convertFieldName(fieldName), String.class);
    }

    public Boolean getBooleanValue(final DataType dataType, final String fieldName) {
        return getValue(dataType, convertFieldName(fieldName), Boolean.class);
    }

    public Integer getIntegerValue(final DataType dataType, final String fieldName) {
        return getValue(dataType, convertFieldName(fieldName), Integer.class);
    }

    public Float getFloatValue(final DataType dataType, final String fieldName) {
        return getValue(dataType, convertFieldName(fieldName), Float.class);
    }

    public Double getDoubleValue(final DataType dataType, final String fieldName) {
        return getValue(dataType, convertFieldName(fieldName), Double.class);
    }

    public Object getObjectValue(final DataType dataType, final String fieldName) {
        return getValue(dataType, convertFieldName(fieldName), Object.class);
    }

    private <T> T getValue(final DataType dataType, final String fieldName, final Class<T> clazz) {
        try {
            return clazz.cast(dataType.getValue(fieldName));
        } catch (final ClassCastException e) {
            throw new RuleEvaluationException("Unable to cast field " + fieldName + " to class " + clazz.getName(), e);
        }
    }

    private String convertFieldName(final String fieldName) {
        final String mappedFieldName = fieldTranslations.get(fieldName);
        return mappedFieldName == null ? fieldName : mappedFieldName;
    }
}
