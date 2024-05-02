package org.opensearch.securityanalytics.ruleengine.parser.sigma.v1;

import org.apache.commons.io.FilenameUtils;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.opensearch.securityanalytics.ruleengine.provider.RuleData;
import org.opensearch.securityanalytics.ruleengine.rules.ParsedRules;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class SigmaV1RuleParserIT {
    private static final String SAP_RULES_DIRECTORY = "../src/main/resources/rules/";

    private final SigmaV1RuleParser sigmaV1RuleParser = new SigmaV1RuleParser(Collections.emptyMap());

    @ParameterizedTest
    @MethodSource("provideRuleSet")
    public void testParseRules(final String rulePath, final RuleData ruleData) {
        try {
            final ParsedRules result = sigmaV1RuleParser.parseRules(ruleData);
            assertEquals(1, result.getStatelessRules().size());
        } catch (final Exception e) {
            if (e instanceof UnsupportedOperationException && e.getMessage().equals("Keyword lookup is not yet supported")) {
                return;
            }

            throw new RuntimeException("Unable to parse rule " + rulePath, e);
        }
    }


    private static Stream<Arguments> provideRuleSet() {
        try {
            return Files.walk(Path.of(SAP_RULES_DIRECTORY))
                    .filter(SigmaV1RuleParserIT::isRuleFile)
                    .map(SigmaV1RuleParserIT::getRuleArguments);
        } catch (final Exception e) {
            throw new RuntimeException("Failed to read rule files", e);
        }
    }

    private static boolean isRuleFile(final Path filePath) {
        final String fileExtension = FilenameUtils.getExtension(filePath.toString());
        return Files.isRegularFile(filePath) && ("yml".equals(fileExtension) || "yaml".equals(fileExtension));
    }

    private static Arguments getRuleArguments(final Path filePath) {
        try {
            final String ruleAsString = Files.readString(filePath);
            final RuleData ruleData = new RuleData(ruleAsString, x -> true, Collections.emptyMap());
            return Arguments.of(filePath.toString(), ruleData);
        } catch (final IOException e) {
            throw new RuntimeException("Failed to read rule file " + filePath, e);
        }
    }
}
