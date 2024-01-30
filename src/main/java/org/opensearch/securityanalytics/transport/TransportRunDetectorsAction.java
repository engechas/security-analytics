/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.bulk.BulkAction;
import org.opensearch.action.bulk.BulkItemResponse;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchAction;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.client.Client;
import org.opensearch.client.node.NodeClient;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.commons.alerting.AlertingPluginInterface;
import org.opensearch.commons.alerting.action.IdDocPair;
import org.opensearch.commons.alerting.action.RunWorkflowRequest;
import org.opensearch.commons.alerting.action.RunWorkflowResponse;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.search.sort.FieldSortBuilder;
import org.opensearch.securityanalytics.action.RunDetectorsAction;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.DetectorInput;
import org.opensearch.securityanalytics.util.DetectorUtils;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class TransportRunDetectorsAction extends HandledTransportAction<BulkRequest, BulkResponse> {

    private static final Logger log = LogManager.getLogger(TransportRunDetectorsAction.class);

    private final ClusterService clusterService;

    private final Settings settings;

    private final Client client;

    private final NamedXContentRegistry xContentRegistry;

    private final ThreadPool threadPool;

    private final TransportSearchDetectorAction transportSearchDetectorAction;

    @Inject
    public TransportRunDetectorsAction(final TransportService transportService,
                                       final Client client,
                                       final NamedXContentRegistry xContentRegistry,
                                       final ClusterService clusterService,
                                       final Settings settings,
                                       final ActionFilters actionFilters,
                                       final TransportSearchDetectorAction transportSearchDetectorAction) {
        super(RunDetectorsAction.NAME, transportService, actionFilters, BulkRequest::new);
        this.client = client;
        this.xContentRegistry = xContentRegistry;
        this.clusterService = clusterService;
        this.settings = settings;
        this.threadPool = this.client.threadPool();
        this.transportSearchDetectorAction = transportSearchDetectorAction;
    }

    @Override
    protected void doExecute(final Task task, final BulkRequest request, final ActionListener<BulkResponse> listener) {
        // TODO - what if SAP fails? What to do with bulk response

        client.execute(BulkAction.INSTANCE, request, new ActionListener<>() {
            @Override
            public void onResponse(final BulkResponse bulkResponse) {
                final Map<String, List<IdDocPair>> indexToIdDocPairs = getIndexToIdDocPairs(request, bulkResponse);
                listDetectors(indexToIdDocPairs, bulkResponse, listener);
            }

            @Override
            public void onFailure(final Exception e) {
                listener.onFailure(SecurityAnalyticsException.wrap(e));
            }
        });
    }

    private Map<String, List<IdDocPair>> getIndexToIdDocPairs(final BulkRequest bulkRequest, final BulkResponse bulkResponse) {
        if (bulkRequest.requests().size() != bulkResponse.getItems().length) {
            throw new SecurityAnalyticsException(
                    "BulkRequest item length did not match BulkResponse item length. Unable to proceed.",
                    RestStatus.INTERNAL_SERVER_ERROR,
                    null
            );
        }

        final Map<String, List<IdDocPair>> indexToIdDocPairs = new HashMap<>();
        IntStream.range(0, bulkRequest.requests().size()).forEach(requestIndex -> {
            final DocWriteRequest<?> request = bulkRequest.requests().get(requestIndex);
            final BulkItemResponse response = bulkResponse.getItems()[requestIndex];

            // No work for SAP to do if doc is being deleted or DocWriteRequest failed
            if (isDeleteOperation(request) || response.isFailed()) {
                return;
            }

            indexToIdDocPairs.putIfAbsent(request.index(), new ArrayList<>());
            final BytesReference document = getDocument(request);
            final String docId = response.getId();
            indexToIdDocPairs.get(request.index()).add(new IdDocPair(docId, document));
        });

        return indexToIdDocPairs;
    }

    private boolean isDeleteOperation(final DocWriteRequest<?> docWriteRequest) {
        return DocWriteRequest.OpType.DELETE.equals(docWriteRequest.opType());
    }

    private BytesReference getDocument(final DocWriteRequest<?> docWriteRequest) {
        switch (docWriteRequest.opType()) {
            case CREATE:
            case INDEX: return ((IndexRequest) docWriteRequest).source();
            case UPDATE: return ((UpdateRequest) docWriteRequest).doc().source();
            default: throw new UnsupportedOperationException("No handler for operation type: " + docWriteRequest.opType());
        }
    }

    private void listDetectors(final Map<String, List<IdDocPair>> indexToIdDocPairs,
                               final BulkResponse bulkResponse,
                               final ActionListener<BulkResponse> listener) {
        final SearchSourceBuilder searchSourceBuilder = SearchSourceBuilder.searchSource()
                .version(true)
                .sort(
                        new FieldSortBuilder("_id")
                                .unmappedType("keyword")
                                .missing("_last")
                )
                .size(10000);

        final SearchRequest searchRequest = new SearchRequest();
        searchRequest.indices(Detector.DETECTORS_INDEX);
        searchRequest.source(searchSourceBuilder);

        // TODO - retries/pagination
        client.execute(SearchAction.INSTANCE, searchRequest, new ActionListener<>() {
            @Override
            public void onResponse(final SearchResponse searchResponse) {
                try {
                    final List<Detector> searchHitDetectors = DetectorUtils.getDetectors(searchResponse, xContentRegistry);
                    getWorkflowIdToDocs(indexToIdDocPairs, searchHitDetectors, bulkResponse, listener);
                } catch (final IOException e) {
                    listener.onFailure(SecurityAnalyticsException.wrap(e));
                }
            }

            @Override
            public void onFailure(final Exception e) {
                if (e instanceof IndexNotFoundException) {
                    log.warn("No detectors configured");
                    listener.onResponse(bulkResponse);
                } else {
                    listener.onFailure(SecurityAnalyticsException.wrap(e));
                }
            }
        });
    }

    private void getWorkflowIdToDocs(final Map<String, List<IdDocPair>> indexToIdDocPairs,
                                     final List<Detector> detectors,
                                     final BulkResponse bulkResponse,
                                     final ActionListener<BulkResponse> listener)  {
        final Map<String, List<IdDocPair>> workflowIdToDocs = new HashMap<>();
        indexToIdDocPairs.forEach((index, idDocPairs) -> {
            final List<String> workflowIds = getWorkflowIdsForIndex(index, detectors);
            workflowIds.forEach(workflowId -> {
                workflowIdToDocs.putIfAbsent(workflowId, new ArrayList<>());
                workflowIdToDocs.get(workflowId).addAll(idDocPairs);
            });
        });

        try {
            if (workflowIdToDocs.isEmpty()) {
                log.info("No workflows to run");
                listener.onResponse(bulkResponse);
            }

            final AtomicInteger workflowSuccessCounter = new AtomicInteger(0);
            workflowIdToDocs.forEach((workflowId, docs) -> {
                log.info("Running workflow with ID {}", workflowId);
                final RunWorkflowRequest runWorkflowRequest = new RunWorkflowRequest(workflowId, docs);
                AlertingPluginInterface.INSTANCE.runWorkflow((NodeClient) client, runWorkflowRequest, new ActionListener<>() {
                    @Override
                    public void onResponse(final RunWorkflowResponse runWorkflowResponse) {
                        log.info("Successfully ran workflow with ID {}", workflowId);
                        workflowSuccessCounter.getAndAdd(1);

                        if (workflowSuccessCounter.get() == workflowIdToDocs.size()) {
                            listener.onResponse(bulkResponse);
                        }
                    }

                    @Override
                    public void onFailure(final Exception e) {
                        listener.onFailure(SecurityAnalyticsException.wrap(e));
                    }
                });
            });
        } catch (final Exception e) {
            listener.onFailure(SecurityAnalyticsException.wrap(e));
        }
    }

    private List<String> getWorkflowIdsForIndex(final String index, final List<Detector> detectors) {
        return detectors.stream()
                .filter(detector -> doesDetectorHaveIndexAsInput(index, detector))
                .map(Detector::getWorkflowIds)
                .flatMap(Collection::stream)
                .collect(Collectors.toList());
    }

    // TODO - edge case on detector created for data stream/alias, but IndexRequest is directly to write index
    private boolean doesDetectorHaveIndexAsInput(final String index, final Detector detector) {
        final List<String> detectorInputs = detector.getInputs().stream()
                .map(DetectorInput::getIndices)
                .flatMap(Collection::stream)
                .collect(Collectors.toList());

        return detectorInputs.contains(index);
    }
}
