package org.opensearch.securityanalytics.ruleengine.rules.metadata;

import java.util.Map;

public class OpenSearchRuleMetadata {
    public static final String MONITOR_ID_FIELD = "monitorId";
    public static final String DETECTOR_NAME_FIELD = "detectorName";
    public static final String FINDINGS_INDEX_FIELD = "findingsIndex";

    private final String monitorId;
    private final String detectorName;
    private final String findingsIndex;

    public OpenSearchRuleMetadata(final Map<String, String> ruleMetadata) {
        this.monitorId = ruleMetadata.get(MONITOR_ID_FIELD);
        this.detectorName = ruleMetadata.get(DETECTOR_NAME_FIELD);
        this.findingsIndex = ruleMetadata.get(FINDINGS_INDEX_FIELD);
    }

    public String getMonitorId() {
        return monitorId;
    }

    public String getDetectorName() {
        return detectorName;
    }

    public String getFindingsIndex() {
        return findingsIndex;
    }
}
