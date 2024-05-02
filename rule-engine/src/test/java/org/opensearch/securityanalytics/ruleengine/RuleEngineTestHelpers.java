/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.ruleengine;

import org.opensearch.securityanalytics.ruleengine.model.DataType;
import org.opensearch.securityanalytics.rules.objects.SigmaRule;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

public class RuleEngineTestHelpers {
    private static final String RULES_PATH_FORMAT = "src/test/resources/rules/sigma/v1/%s";

    public static class MapDataType extends DataType {
        private final Map<String, Object> fields;

        public MapDataType(final Map<String, Object> fields) {
            this.fields = fields;
        }

        @Override
        public Object getValue(final String fieldName) {
            return fields.get(fieldName);
        }

        @Override
        public String getTimeFieldName() {
            return null;
        }
    }

    public static DataType getDataType(final Map<String, Object> fields) {
        return new RuleEngineTestHelpers.MapDataType(fields);
    }

    public static SigmaRule getSampleSigmaRule() {
        return getSigmaRuleFromFile("sample-rule.yml");
    }

    public static SigmaRule getSigmaRuleFromFile(final String ruleFile) {
        return getSigmaRuleFromPathAndFile(RULES_PATH_FORMAT, ruleFile);
    }

    public static SigmaRule getSigmaRuleFromPathAndFile(final String pathFormat, final String ruleFile) {
        return getSigmaRuleFromPath(String.format(pathFormat, ruleFile));
    }

    public static SigmaRule getSigmaRuleFromPath(final String rulePathAsString) {
        try {
            final Path rulePath = Path.of(rulePathAsString);
            final String ruleString = Files.readString(rulePath, StandardCharsets.UTF_8);

            return SigmaRule.fromYaml(ruleString, true);
        } catch (final Exception e) {
            throw new RuntimeException("Exception parsing rule from path: " + rulePathAsString, e);
        }
    }
}
