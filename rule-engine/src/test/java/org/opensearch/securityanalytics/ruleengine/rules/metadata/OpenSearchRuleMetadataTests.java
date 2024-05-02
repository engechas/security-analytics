package org.opensearch.securityanalytics.ruleengine.rules.metadata;

import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

public class OpenSearchRuleMetadataTests {

    @Test
    public void testConstructor() {
        final Map<String, String> ruleMetadata = Map.of(
                OpenSearchRuleMetadata.MONITOR_ID_FIELD, UUID.randomUUID().toString(),
                OpenSearchRuleMetadata.DETECTOR_NAME_FIELD, UUID.randomUUID().toString(),
                OpenSearchRuleMetadata.FINDINGS_INDEX_FIELD, UUID.randomUUID().toString()
        );

        final OpenSearchRuleMetadata result = new OpenSearchRuleMetadata(ruleMetadata);

        assertEquals(ruleMetadata.get(OpenSearchRuleMetadata.MONITOR_ID_FIELD), result.getMonitorId());
        assertEquals(ruleMetadata.get(OpenSearchRuleMetadata.DETECTOR_NAME_FIELD), result.getDetectorName());
        assertEquals(ruleMetadata.get(OpenSearchRuleMetadata.FINDINGS_INDEX_FIELD), result.getFindingsIndex());
    }

    @Test
    public void testConstructor_NullValues() {
        final OpenSearchRuleMetadata result = new OpenSearchRuleMetadata(Collections.emptyMap());

        assertNull(result.getMonitorId());
        assertNull(result.getDetectorName());
        assertNull(result.getFindingsIndex());
    }
}
