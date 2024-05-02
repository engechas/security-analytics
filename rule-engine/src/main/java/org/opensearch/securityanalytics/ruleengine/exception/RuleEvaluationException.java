/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.ruleengine.exception;

public class RuleEvaluationException extends RuntimeException {
    public RuleEvaluationException(final String message) {
        super(message);
    }
    public RuleEvaluationException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
