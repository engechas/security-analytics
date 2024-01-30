/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class RunDetectorsRequest extends ActionRequest {
    public static final String INDEX_INFO_FIELD = "indexInfo";

    private final List<IndexInfo> indexInfo;

    public RunDetectorsRequest(final List<IndexInfo> indexInfo) {
        super();
        this.indexInfo = indexInfo;
    }

    public RunDetectorsRequest(final StreamInput sin) throws IOException {
        this(
                sin.readList(IndexInfo::readFrom)
        );
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    public List<IndexInfo> getIndexInfo() {
        return indexInfo;
    }

    public static RunDetectorsRequest parse(final XContentParser xcp) throws IOException {
        final List<IndexInfo> indexInfo = new ArrayList<>();

        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);

        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            final String fieldName = xcp.currentName();
            xcp.nextToken();

            switch (fieldName) {
                case INDEX_INFO_FIELD:
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        final IndexInfo indexInfoEntry = IndexInfo.parse(xcp);
                        indexInfo.add(indexInfoEntry);
                    }
                    break;
                default:
                    xcp.skipChildren();
            }
        }

        return new RunDetectorsRequest(indexInfo);
    }
}
