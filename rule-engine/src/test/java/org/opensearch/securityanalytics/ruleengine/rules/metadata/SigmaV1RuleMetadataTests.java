package org.opensearch.securityanalytics.ruleengine.rules.metadata;

import org.junit.jupiter.api.Test;
import org.opensearch.securityanalytics.ruleengine.RuleEngineTestHelpers;
import org.opensearch.securityanalytics.rules.objects.SigmaRule;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class SigmaV1RuleMetadataTests {
    @Test
    public void testConstructor() {
        final SigmaRule sigmaRule = RuleEngineTestHelpers.getSampleSigmaRule();

        final SigmaV1RuleMetadata result = new SigmaV1RuleMetadata(sigmaRule);

        assertEquals("AWS Lambda Function Created or Invoked", result.getTitle());
        assertEquals(4, result.getTags().size());
        assertEquals("low", result.getTags().get(0));
        assertEquals("cloudtrail", result.getTags().get(1));
        assertEquals("attack.privilege_escalation", result.getTags().get(2));
        assertEquals("attack.t1078", result.getTags().get(3));
    }
}
