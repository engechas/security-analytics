/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionType;
import org.opensearch.action.bulk.BulkResponse;

public class RunDetectorsAction extends ActionType<BulkResponse> {
    public static final RunDetectorsAction INSTANCE = new RunDetectorsAction();
    public static final String NAME = "cluster:admin/opensearch/securityanalytics/detectors/run";

    public RunDetectorsAction() {
        super(NAME, BulkResponse::new);
    }
}