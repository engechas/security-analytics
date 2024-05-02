/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.ruleengine.parser.sigma.v1;

import org.opensearch.securityanalytics.ruleengine.exception.RuleParseException;
import org.opensearch.securityanalytics.ruleengine.field.FieldAccessor;
import org.opensearch.securityanalytics.ruleengine.model.DataType;
import org.opensearch.securityanalytics.rules.condition.ConditionAND;
import org.opensearch.securityanalytics.rules.condition.ConditionFieldEqualsValueExpression;
import org.opensearch.securityanalytics.rules.condition.ConditionItem;
import org.opensearch.securityanalytics.rules.condition.ConditionNOT;
import org.opensearch.securityanalytics.rules.condition.ConditionOR;
import org.opensearch.securityanalytics.rules.condition.ConditionValueExpression;
import org.opensearch.securityanalytics.rules.types.SigmaExpansion;
import org.opensearch.securityanalytics.rules.types.SigmaType;
import org.opensearch.securityanalytics.rules.utils.AnyOneOf;
import org.opensearch.securityanalytics.rules.utils.Either;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;
import java.util.stream.Collectors;

public class SigmaV1ConditionParser {

    private final SigmaV1LeafConditionParser sigmaV1LeafConditionParser;

    public SigmaV1ConditionParser(final FieldAccessor fieldAccessor) {
        this.sigmaV1LeafConditionParser = new SigmaV1LeafConditionParser(fieldAccessor);
    }

    // Visible for testing
    SigmaV1ConditionParser(final SigmaV1LeafConditionParser sigmaV1LeafConditionParser) {
        this.sigmaV1LeafConditionParser = sigmaV1LeafConditionParser;
    }

    public Predicate<DataType> parseRuleCondition(final List<ConditionItem> conditionItems) {
        return conditionItems.stream()
                .map(this::parsePredicateFromConditionItem)
                // Multiple conditions can be defined for a single rule. The Sigma V1 specification says these should be joined with a logical OR
                .reduce(Predicate::or)
                // Default to no match if there were no predicates
                .orElse(x -> false);
    }

    private Predicate<DataType> parsePredicateFromConditionItem(final ConditionItem conditionItem) {
        if (conditionItem instanceof ConditionAND) {
            return convertAndCondition(conditionItem);
        } else if (conditionItem instanceof ConditionOR) {
            return convertOrCondition(conditionItem);
        } else if (conditionItem instanceof ConditionNOT) {
            return convertNotCondition(conditionItem);
        } else if (conditionItem instanceof ConditionFieldEqualsValueExpression) {
            return convertFieldEquals((ConditionFieldEqualsValueExpression) conditionItem);
        } else if (conditionItem instanceof ConditionValueExpression) {
            // Keyword lookup refers to searching the set of values for one or more terms rather than key-based lookup
            throw new UnsupportedOperationException("Keyword lookup is not yet supported");
        } else {
            throw new RuleParseException("Unexpected condition type class in condition parse tree: " + conditionItem.getClass().getName());
        }
    }

    private Predicate<DataType> convertAndCondition(final ConditionItem condition) {
        final List<Predicate<DataType>> conditionPredicates = getPredicatesFromConditions(condition);
        validateConditionLeafCount(conditionPredicates, "AND", condition.getArgs().size());

        return conditionPredicates.stream()
                .reduce(Predicate::and)
                .orElseThrow(() -> new RuleParseException("No predicates found for AND expression"));
    }

    private Predicate<DataType> convertOrCondition(final ConditionItem condition) {
        final List<Predicate<DataType>> conditionPredicates = getPredicatesFromConditions(condition);
        validateConditionLeafCount(conditionPredicates, "OR", condition.getArgs().size());

        return conditionPredicates.stream()
                .reduce(Predicate::or)
                .orElseThrow(() -> new RuleParseException("No predicates found for OR expression"));
    }

    private Predicate<DataType> convertNotCondition(final ConditionItem condition) {
        final List<Predicate<DataType>> conditionPredicates = getPredicatesFromConditions(condition);
        validateConditionLeafCount(conditionPredicates, "NOT", condition.getArgs().size());

        return conditionPredicates.stream()
                .map(Predicate::negate)
                .findFirst()
                .orElseThrow(() -> new RuleParseException("No predicates found for NOT expression"));
    }

    private List<Predicate<DataType>> getPredicatesFromConditions(final ConditionItem condition) {
        return condition.getArgs().stream()
                /* Filter on "is another condition". The Right object would be a reference to another condition
                   which should have be resolved into the actual condition by this point */
                .filter(Either::isLeft)
                .map(Either::getLeft)
                .map(anyOneOf -> {
                    if (anyOneOf.isLeft()) return anyOneOf.getLeft();
                    if (anyOneOf.isMiddle()) return anyOneOf.getMiddle();
                    if (anyOneOf.isRight()) return anyOneOf.get();

                    throw new RuleParseException("Unable to parse inner condition");
                })
                .map(this::parsePredicateFromConditionItem)
                .collect(Collectors.toList());
    }

    private void validateConditionLeafCount(final List<Predicate<DataType>> conditionPredicates, final String operatorName, final int expectedSize) {
        if (conditionPredicates.size() != expectedSize) {
            throw new RuleParseException("Unexpected number of conditions for " + operatorName + " expression. Expected " +
                    expectedSize + ". Found " + conditionPredicates.size());
        }
    }

    private Predicate<DataType> convertFieldEquals(final ConditionFieldEqualsValueExpression condition) {
        if (condition.getValue() instanceof SigmaExpansion) {
            return convertSigmaExpansion(condition);
        }

        return sigmaV1LeafConditionParser.parseLeafCondition(condition);
    }

    private Predicate<DataType> convertSigmaExpansion(final ConditionFieldEqualsValueExpression condition) {
        final List<Either<AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>, String>> args = new ArrayList<>();
        for (SigmaType sigmaType: ((SigmaExpansion) condition.getValue()).getValues()) {
            args.add(Either.left(AnyOneOf.middleVal(new ConditionFieldEqualsValueExpression(condition.getField(), sigmaType))));
        }

        final ConditionOR conditionOR = new ConditionOR(false, args);
        return convertOrCondition(conditionOR);
    }
}
