/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;

import java.io.IOException;

public class RunDetectorsResponse extends ActionResponse implements ToXContentObject {
    private final RestStatus restStatus;

    public RunDetectorsResponse(final RestStatus restStatus) {
        this.restStatus = restStatus;
    }

    public RunDetectorsResponse(final StreamInput streamInput) throws IOException {
        this(
                streamInput.readEnum(RestStatus.class)
        );
    }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
    }

    @Override
    public XContentBuilder toXContent(final XContentBuilder builder, final Params params) throws IOException {
        return builder;
    }
}
