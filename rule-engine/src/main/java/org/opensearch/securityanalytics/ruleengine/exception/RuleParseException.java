/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.ruleengine.exception;

public class RuleParseException extends RuntimeException {
    public RuleParseException(final String message) {
        super(message);
    }

    public RuleParseException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
