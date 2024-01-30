/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.action;

import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.common.io.stream.Writeable;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class IndexInfo implements ToXContentObject, Writeable {
    private static final String INDEX_FIELD = "index";
    private static final String DOCUMENTS_FIELD = "documents";

    private final String index;
    private final List<BytesReference> documents;

    public IndexInfo(final String index, final List<BytesReference> documents) {
        this.index = index;
        this.documents = documents;
    }

    public IndexInfo(final StreamInput sin) throws IOException {
        this(
                sin.readString(),
                sin.readList(StreamInput::readBytesReference)
        );
    }

    @Override
    public void writeTo(final StreamOutput out) throws IOException {
        out.writeString(index);
        out.writeCollection(documents, StreamOutput::writeBytesReference);
    }

    @Override
    public XContentBuilder toXContent(final XContentBuilder builder, final Params params) throws IOException {
        builder.startObject()
                .field(INDEX_FIELD, index)
                .field(DOCUMENTS_FIELD, documents);
        builder.endObject();
        return builder;
    }

    public static IndexInfo readFrom(final StreamInput sin) throws IOException {
        return new IndexInfo(sin);
    }

    public static IndexInfo parse(final XContentParser xcp) throws IOException {
        String index = null;
        List<BytesReference> documents = new ArrayList<>();

        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);

        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            final String fieldName = xcp.currentName();
            xcp.nextToken();

            switch (fieldName) {
                case INDEX_FIELD:
                    index = xcp.text();
                    break;
                case DOCUMENTS_FIELD:
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        final XContentBuilder xContentBuilder = XContentBuilder.builder(xcp.contentType().xContent());
                        xContentBuilder.copyCurrentStructure(xcp);
                        final BytesReference document = BytesReference.bytes(xContentBuilder);
                        documents.add(document);
                    }
                    break;
                default:
                    xcp.skipChildren();
            }
        }

        return new IndexInfo(index, documents);
    }

    public String getIndex() {
        return index;
    }

    public List<BytesReference> getDocuments() {
        return documents;
    }
}
