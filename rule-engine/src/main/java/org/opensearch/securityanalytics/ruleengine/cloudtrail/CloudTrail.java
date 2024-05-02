/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.ruleengine.cloudtrail;

import org.opensearch.securityanalytics.ruleengine.model.DataType;

public class CloudTrail extends DataType {
    // TODO - versioning on log types
    private String eventName;
    private long time;

    public CloudTrail() {
        super();
    }

    @Override
    public Object getValue(final String fieldName) {
        switch (fieldName) {
            case "eventName": return eventName;
            case "time": return time;
            default: throw new UnsupportedOperationException("Unknown field name: " + fieldName);
        }
    }

    @Override
    public String getTimeFieldName() {
        return "time";
    }

    public void setEventName(final String eventName) {
        this.eventName = eventName;
    }

    public void setTime(final long time) {
        this.time = time;
    }
}
