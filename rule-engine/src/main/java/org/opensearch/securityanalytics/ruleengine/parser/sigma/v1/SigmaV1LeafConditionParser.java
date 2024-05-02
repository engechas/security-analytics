/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.ruleengine.parser.sigma.v1;

import inet.ipaddr.IPAddressString;
import org.opensearch.securityanalytics.ruleengine.exception.RuleParseException;
import org.opensearch.securityanalytics.ruleengine.field.FieldAccessor;
import org.opensearch.securityanalytics.ruleengine.model.DataType;
import org.opensearch.securityanalytics.rules.condition.ConditionFieldEqualsValueExpression;
import org.opensearch.securityanalytics.rules.types.SigmaBool;
import org.opensearch.securityanalytics.rules.types.SigmaCIDRExpression;
import org.opensearch.securityanalytics.rules.types.SigmaCompareExpression;
import org.opensearch.securityanalytics.rules.types.SigmaNull;
import org.opensearch.securityanalytics.rules.types.SigmaNumber;
import org.opensearch.securityanalytics.rules.types.SigmaRegularExpression;
import org.opensearch.securityanalytics.rules.types.SigmaString;
import org.opensearch.securityanalytics.rules.types.SigmaType;
import org.opensearch.securityanalytics.rules.utils.Either;

import java.util.function.Predicate;
import java.util.regex.Pattern;

public class SigmaV1LeafConditionParser {
    private final FieldAccessor fieldAccessor;

    public SigmaV1LeafConditionParser(final FieldAccessor fieldAccessor) {
        this.fieldAccessor = fieldAccessor;
    }

    public Predicate<DataType> parseLeafCondition(final ConditionFieldEqualsValueExpression condition) {
        final SigmaType conditionValue = condition.getValue();

        if (conditionValue instanceof SigmaString) {
            return convertStringEquals(condition);
        } else if (conditionValue instanceof SigmaBool) {
            return convertBooleanEquals(condition);
        } else if (conditionValue instanceof SigmaNumber) {
            return convertNumberEquals(condition);
        } else if (conditionValue instanceof SigmaNull) {
            return convertNullEquals(condition);
        } else if (conditionValue instanceof SigmaRegularExpression) {
            return convertRegularExpressionEquals(condition);
        } else if (conditionValue instanceof SigmaCIDRExpression) {
            return convertCIDRContains(condition);
        } else if (conditionValue instanceof SigmaCompareExpression) {
            return convertNumericCompare(condition);
        } else {
            throw new RuleParseException("Unexpected value type class in condition parse tree: " + conditionValue.getClass().getName());
        }
    }

    private Predicate<DataType> convertStringEquals(final ConditionFieldEqualsValueExpression condition) {
        final SigmaString sigmaString = (SigmaString) condition.getValue();
        return dataType -> {
            final String value = fieldAccessor.getStringValue(dataType, condition.getField());
            return sigmaString.getOriginal().equals(value);
        };
    }

    private Predicate<DataType> convertBooleanEquals(final ConditionFieldEqualsValueExpression condition) {
        final SigmaBool sigmaBool = (SigmaBool) condition.getValue();
        return dataType -> ((Boolean) sigmaBool.isaBoolean()).equals(fieldAccessor.getBooleanValue(dataType, condition.getField()));
    }

    private Predicate<DataType> convertNumberEquals(final ConditionFieldEqualsValueExpression condition) {
        final SigmaNumber sigmaNumber = (SigmaNumber) condition.getValue();
        final Either<Integer, Float> integerOrFloat = sigmaNumber.getNumOpt();

        if (integerOrFloat.isLeft()) {
            return convertIntegerEquals(condition.getField(), integerOrFloat.getLeft());
        } else if (integerOrFloat.isRight()) {
            return convertFloatEquals(condition.getField(), integerOrFloat.get());
        } else {
            throw new RuleParseException("SigmaNumber Either for field " + condition.getField() + " was neither left or right.");
        }
    }

    private Predicate<DataType> convertIntegerEquals(final String fieldName, final Integer integerValue) {
        return dataType -> integerValue.equals(fieldAccessor.getIntegerValue(dataType, fieldName));
    }

    private Predicate<DataType> convertFloatEquals(final String fieldName, final Float floatValue) {
        return dataType -> floatValue.equals(fieldAccessor.getFloatValue(dataType, fieldName));
    }

    private Predicate<DataType> convertNullEquals(final ConditionFieldEqualsValueExpression condition) {
        return dataType -> fieldAccessor.getObjectValue(dataType, condition.getField()) == null;
    }

    private Predicate<DataType> convertRegularExpressionEquals(final ConditionFieldEqualsValueExpression condition) {
        final SigmaRegularExpression sigmaRegularExpression = (SigmaRegularExpression) condition.getValue();
        final Pattern pattern = Pattern.compile(sigmaRegularExpression.getRegexp());

        return dataType -> {
            final String fieldValue = fieldAccessor.getStringValue(dataType, condition.getField());
            if (fieldValue == null) {
                return false;
            }

            return pattern.matcher(fieldValue).find();
        };
    }

    private Predicate<DataType> convertCIDRContains(final ConditionFieldEqualsValueExpression condition) {
        final SigmaCIDRExpression sigmaCIDRExpression = (SigmaCIDRExpression) condition.getValue();
        final IPAddressString cidr = new IPAddressString(sigmaCIDRExpression.getCidr());

        return dataType -> {
            final String fieldValue = fieldAccessor.getStringValue(dataType, condition.getField());
            if (fieldValue == null) {
                return false;
            }

            return cidr.contains(new IPAddressString(fieldValue));
        };
    }

    private Predicate<DataType> convertNumericCompare(final ConditionFieldEqualsValueExpression condition) {
        final SigmaCompareExpression sigmaCompareExpression = (SigmaCompareExpression) condition.getValue();
        final SigmaNumber sigmaNumber = sigmaCompareExpression.getNumber();
        final String operator = sigmaCompareExpression.getOp();

        final Float sigmaNumberAsFloat = getSigmaNumberAsFloat(sigmaNumber, condition.getField());

        return dataType -> applyOperator(sigmaNumberAsFloat, operator, dataType, condition);
    }

    private boolean applyOperator(final Float sigmaNumberAsFloat, final String operator, final DataType dataType,
                                  final ConditionFieldEqualsValueExpression condition) {
        final Float fieldValue = fieldAccessor.getFloatValue(dataType, condition.getField());
        if (fieldValue == null) {
            return false;
        }

        return switch (operator) {
            case ">" -> fieldValue > sigmaNumberAsFloat;
            case "<" -> fieldValue < sigmaNumberAsFloat;
            case ">=" -> fieldValue >= sigmaNumberAsFloat;
            case "<=" -> fieldValue <= sigmaNumberAsFloat;
            default -> throw new RuleParseException("Unexpected operator " + operator + " for field " + condition.getField());
        };
    }

    private Float getSigmaNumberAsFloat(final SigmaNumber sigmaNumber, final String fieldName) {
        final Either<Integer, Float> integerOrFloat = sigmaNumber.getNumOpt();

        if (integerOrFloat.isLeft()) {
            return Float.valueOf(integerOrFloat.getLeft());
        } else if (integerOrFloat.isRight()) {
            return integerOrFloat.get();
        } else {
            throw new RuleParseException("SigmaNumber Either for field " + fieldName + " was neither left or right.");
        }
    }
}
