/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.bulk.BulkAction;
import org.opensearch.action.bulk.BulkItemResponse;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.search.SearchAction;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.client.Client;
import org.opensearch.client.node.NodeClient;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.lucene.uid.Versions;
import org.opensearch.common.settings.Settings;
import org.opensearch.commons.alerting.AlertingPluginInterface;
import org.opensearch.commons.alerting.action.ExecuteStreamingWorkflowRequest;
import org.opensearch.commons.alerting.action.ExecuteStreamingWorkflowResponse;
import org.opensearch.commons.alerting.action.GetMonitorRequest;
import org.opensearch.commons.alerting.action.GetMonitorResponse;
import org.opensearch.commons.alerting.model.DocLevelMonitorInput;
import org.opensearch.commons.alerting.model.DocLevelQuery;
import org.opensearch.commons.alerting.model.Monitor;
import org.opensearch.commons.authuser.User;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.rest.RestRequest;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.action.ExecuteStreamingDetectorsAction;
import org.opensearch.securityanalytics.converters.ExecuteStreamingWorkflowRequestConverter;
import org.opensearch.securityanalytics.converters.IndexNameToDocDataConverter;
import org.opensearch.securityanalytics.converters.StreamingDetectorMetadataConverter;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.DocData;
import org.opensearch.securityanalytics.model.StreamingDetectorMetadata;
import org.opensearch.securityanalytics.util.DetectorUtils;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

public class TransportExecuteStreamingDetectorsAction extends HandledTransportAction<BulkRequest, BulkResponse> implements SecureTransportAction {
    private static final Logger log = LogManager.getLogger(TransportExecuteStreamingDetectorsAction.class);

    private final ClusterService clusterService;

    private final Settings settings;

    private final Client client;

    private final ThreadPool threadPool;

    private final NamedXContentRegistry xContentRegistry;

    private final TransportSearchDetectorAction transportSearchDetectorAction;

    private final IndexNameToDocDataConverter indexNameToDocDataConverter;

    private final StreamingDetectorMetadataConverter streamingDetectorMetadataConverter;

    private final ExecuteStreamingWorkflowRequestConverter executeStreamingWorkflowRequestConverter;

    @Inject
    public TransportExecuteStreamingDetectorsAction(final TransportService transportService,
                                                    final Client client,
                                                    final ClusterService clusterService,
                                                    final Settings settings,
                                                    final ActionFilters actionFilters,
                                                    final NamedXContentRegistry xContentRegistry,
                                                    final TransportSearchDetectorAction transportSearchDetectorAction,
                                                    final IndexNameToDocDataConverter indexNameToDocDataConverter,
                                                    final StreamingDetectorMetadataConverter streamingDetectorMetadataConverter,
                                                    final ExecuteStreamingWorkflowRequestConverter executeStreamingWorkflowRequestConverter) {
        super(ExecuteStreamingDetectorsAction.NAME, transportService, actionFilters, BulkRequest::new);
        this.client = client;
        this.clusterService = clusterService;
        this.settings = settings;
        this.threadPool = this.client.threadPool();
        this.xContentRegistry = xContentRegistry;
        this.transportSearchDetectorAction = transportSearchDetectorAction;
        this.indexNameToDocDataConverter = indexNameToDocDataConverter;
        this.streamingDetectorMetadataConverter = streamingDetectorMetadataConverter;
        this.executeStreamingWorkflowRequestConverter = executeStreamingWorkflowRequestConverter;
    }

    /**
     * Executes the following steps sequentially
     * 1. Submit the BulkRequest for indexing
     * 2. Identify the detectors associated with the indices being written to
     * 3. Get the query fields associated with the underlying monitors
     * 4. Filter the documents based on the query fields of the underlying monitors
     * 5. Pair the filtered documents to their corresponding detector(s)
     * 6. Execute the underlying workflows for each relevant detector
     *
     * If there are any failures in the steps after the BulkRequest is indexed, the corresponding BulkItemResponses
     * are updated with a RestStatus of 424 and details about the failure
     */
    @Override
    protected void doExecute(final Task task, final BulkRequest bulkRequest, final ActionListener<BulkResponse> listener) {
        final long operationStartTime = System.currentTimeMillis();

        if (!validateUser()) {
            listener.onFailure(SecurityAnalyticsException.wrap(
                    new OpenSearchStatusException("User is not authorized to to perform this action. Contact administrator", RestStatus.FORBIDDEN)
            ));
            return;
        }

        final long startTime = System.currentTimeMillis();
        client.execute(BulkAction.INSTANCE, bulkRequest, new ActionListener<>() {
            @Override
            public void onResponse(final BulkResponse bulkResponse) {
                logDuration(startTime, "Execute BulkRequest");
                identifyDetectors(bulkRequest, bulkResponse, listener, operationStartTime);
            }

            @Override
            public void onFailure(final Exception e) {
                listener.onFailure(e);
            }
        });
    }

    private boolean validateUser() {
        final User user = readUserFromThreadContext(client.threadPool());

        // If security is enabled, only allow the admin user to call this API
        return user == null || isAdmin(user);
    }

    private void identifyDetectors(final BulkRequest bulkRequest, final BulkResponse bulkResponse,
                                   final ActionListener<BulkResponse> listener, final long operationStartTime) {
        final Map<String, List<DocData>> indexToDocData = indexNameToDocDataConverter.convert(bulkRequest, bulkResponse);
        final SearchRequest listDetectorsRequest = getListDetectorsRequest();

        final long startTime = System.currentTimeMillis();
        client.execute(SearchAction.INSTANCE, listDetectorsRequest, new ActionListener<>() {
            @Override
            public void onResponse(final SearchResponse searchResponse) {
                logDuration(startTime, "List Detectors");

                final List<Detector> detectors;
                try {
                    detectors = DetectorUtils.getDetectors(searchResponse, xContentRegistry);
                } catch (final IOException e) {
                    handleAllDetectorsFailure(bulkResponse, indexToDocData, e);
                    listener.onResponse(recreateBulkResponseWithCorrectTookMillis(operationStartTime, bulkResponse));
                    return;
                }

                getMonitors(indexToDocData, detectors, listener, bulkResponse, operationStartTime);
            }

            @Override
            public void onFailure(final Exception e) {
                if (e instanceof IndexNotFoundException) {
                    log.warn("No detectors configured, skipping streaming detectors workflow");
                    listener.onResponse(recreateBulkResponseWithCorrectTookMillis(operationStartTime, bulkResponse));
                } else {
                    handleAllDetectorsFailure(bulkResponse, indexToDocData, e);
                    listener.onResponse(recreateBulkResponseWithCorrectTookMillis(operationStartTime, bulkResponse));
                }
            }
        });
    }

    private SearchRequest getListDetectorsRequest() {
        final SearchSourceBuilder searchSourceBuilder = SearchSourceBuilder.searchSource().size(10000); // TODO - pagination
        final SearchRequest searchRequest = new SearchRequest();
        searchRequest.indices(Detector.DETECTORS_INDEX);
        searchRequest.source(searchSourceBuilder);

        return searchRequest;
    }

    private void getMonitors(final Map<String, List<DocData>> indexToDocData,
                             final List<Detector> detectors,
                             final ActionListener<BulkResponse> listener,
                             final BulkResponse bulkResponse,
                             final long operationStartTime) {
        final List<StreamingDetectorMetadata> streamingDetectors = streamingDetectorMetadataConverter.convert(detectors, indexToDocData);
        if (streamingDetectors.isEmpty()) {
            log.debug("No streaming detectors identified for incoming data. Skipping streaming detectors workflow");
            listener.onResponse(recreateBulkResponseWithCorrectTookMillis(operationStartTime, bulkResponse));
            return;
        }

        final Map<String, StreamingDetectorMetadata> monitorIdToMetadata = new HashMap<>();
        streamingDetectors.forEach(streamingDetector -> {
            streamingDetector.getMonitorIds().forEach(monitorId -> monitorIdToMetadata.put(monitorId, streamingDetector));
        });

        final AtomicInteger getMonitorCounter = new AtomicInteger(0);
        final long startTime = System.currentTimeMillis();
        // TODO - this pattern will submit a burst of requests if the detector/monitor/workflow count is high. Rate limiting should be applied
        monitorIdToMetadata.keySet().forEach(monitorId -> {
            final GetMonitorRequest getMonitorRequest = new GetMonitorRequest(monitorId, Versions.MATCH_ANY, RestRequest.Method.GET, null);
            AlertingPluginInterface.INSTANCE.getMonitor((NodeClient) client, getMonitorRequest, new ActionListener<>() {
                @Override
                public void onResponse(final GetMonitorResponse getMonitorResponse) {
                    populateWorkflowIdToMetadata(monitorId, getMonitorResponse, monitorIdToMetadata, streamingDetectors,
                            getMonitorCounter, listener, bulkResponse, startTime, operationStartTime);
                }

                @Override
                public void onFailure(final Exception e) {
                    handleDetectorFailure(bulkResponse, monitorIdToMetadata.get(monitorId), e);

                    getMonitorCounter.incrementAndGet();
                    if (getMonitorCounter.get() == monitorIdToMetadata.size()) {
                        listener.onResponse(recreateBulkResponseWithCorrectTookMillis(operationStartTime, bulkResponse));
                    }
                }
            });
        });
    }

    private void populateWorkflowIdToMetadata(final String monitorId,
                                              final GetMonitorResponse getMonitorResponse,
                                              final Map<String, StreamingDetectorMetadata> monitorIdToMetadata,
                                              final List<StreamingDetectorMetadata> streamingDetectors,
                                              final AtomicInteger getMonitorCounter,
                                              final ActionListener<BulkResponse> listener,
                                              final BulkResponse bulkResponse,
                                              final long startTime,
                                              final long operationStartTime) {
        final StreamingDetectorMetadata metadata = monitorIdToMetadata.get(monitorId);
        if (isMonitorValidForStreaming(getMonitorResponse)) {
            populateQueryFields(getMonitorResponse.getMonitor(), metadata);

            getMonitorCounter.incrementAndGet();
            if (getMonitorCounter.get() == monitorIdToMetadata.size()) {
                logDuration(startTime, "Get and Populate Query Fields");
                executeWorkflows(streamingDetectors, listener, bulkResponse, operationStartTime);
            }
        } else {
            final String errorMsg = String.format("Monitor with ID %s is invalid for streaming.", monitorId);
            final SecurityAnalyticsException exception = new SecurityAnalyticsException(errorMsg, RestStatus.INTERNAL_SERVER_ERROR, null);
            handleDetectorFailure(bulkResponse, metadata, exception);

            getMonitorCounter.incrementAndGet();
            if (getMonitorCounter.get() == monitorIdToMetadata.size()) {
                listener.onResponse(recreateBulkResponseWithCorrectTookMillis(operationStartTime, bulkResponse));
            }
        }
    }

    private boolean isMonitorValidForStreaming(final GetMonitorResponse getMonitorResponse) {
        return getMonitorResponse.getMonitor() != null && getMonitorResponse.getMonitor().getInputs().size() == 1;
    }

    private void populateQueryFields(final Monitor monitor, final StreamingDetectorMetadata metadata) {
        final DocLevelMonitorInput docLevelMonitorInput = (DocLevelMonitorInput) monitor.getInputs().get(0);
        final Set<String> fieldNames = docLevelMonitorInput.getQueries().stream()
                .map(DocLevelQuery::getQueryFieldNames)
                .flatMap(Collection::stream)
                .collect(Collectors.toSet());

        metadata.addQueryFields(fieldNames);
    }

    private void executeWorkflows(final Collection<StreamingDetectorMetadata> streamingDetectors,
                                  final ActionListener<BulkResponse> listener,
                                  final BulkResponse bulkResponse,
                                  final long operationStartTime) {
        final AtomicInteger workflowExecutionCounter = new AtomicInteger(0);
        final long startTime = System.currentTimeMillis();
        streamingDetectors.forEach(streamingDetector -> {
            final ExecuteStreamingWorkflowRequest executeWorkflowRequest = executeStreamingWorkflowRequestConverter.convert(streamingDetector);
            executeWorkflow(executeWorkflowRequest, streamingDetector, workflowExecutionCounter, streamingDetectors.size(),
                    listener, bulkResponse, startTime, operationStartTime);
        });
    }

    private void executeWorkflow(final ExecuteStreamingWorkflowRequest executeWorkflowRequest, final StreamingDetectorMetadata streamingDetector,
                                 final AtomicInteger workflowExecutionCounter, final int workflowCount,
                                 final ActionListener<BulkResponse> listener, final BulkResponse bulkResponse,
                                 final long startTime, final long operationStartTime) {
        AlertingPluginInterface.INSTANCE.executeStreamingWorkflow((NodeClient) client, executeWorkflowRequest, new ActionListener<>() {
            @Override
            public void onResponse(final ExecuteStreamingWorkflowResponse executeStreamingWorkflowResponse) {
                log.debug("Successfully ran workflow with ID {}", executeWorkflowRequest.getWorkflowId());
                workflowExecutionCounter.incrementAndGet();

                if (workflowExecutionCounter.get() == workflowCount) {
                    logDuration(startTime, "Execute Workflows");
                    listener.onResponse(recreateBulkResponseWithCorrectTookMillis(operationStartTime, bulkResponse));
                }
            }

            @Override
            public void onFailure(final Exception e) {
                log.error("Failed to run workflow with ID {}", executeWorkflowRequest.getWorkflowId());
                handleDetectorFailure(bulkResponse, streamingDetector, e);

                workflowExecutionCounter.incrementAndGet();
                if (workflowExecutionCounter.get() == workflowCount) {
                    listener.onResponse(recreateBulkResponseWithCorrectTookMillis(operationStartTime, bulkResponse));
                }
            }
        });
    }

    private BulkResponse recreateBulkResponseWithCorrectTookMillis(final long startTime, final BulkResponse bulkResponse) {
        final long tookMillis = System.currentTimeMillis() - startTime;
        return new BulkResponse(bulkResponse.getItems(), tookMillis, bulkResponse.getIngestTookInMillis());
    }

    private void handleAllDetectorsFailure(final BulkResponse bulkResponse, final Map<String, List<DocData>> indexToDocData,
                                           final Exception exception) {
        log.error("Failed to run all detectors", exception);
        final String failureMessage = String.format("Failed to run all detectors due to %s.", exception);

        // Only get the indices of documents that were eligible to be sent to a detector workflow
        final Set<Integer> bulkItemResponseArrayIndices = indexToDocData.values().stream()
                .flatMap(Collection::stream)
                .map(DocData::getBulkItemResponseIndex)
                .collect(Collectors.toSet());

        bulkItemResponseArrayIndices.forEach(i -> {
            final BulkItemResponse originalBulkItemResponse = bulkResponse.getItems()[i];
            final BulkItemResponse recreatedBulkItemResponse = recreateBulkItemResponseWithFailure(originalBulkItemResponse, failureMessage);
            bulkResponse.getItems()[i] = recreatedBulkItemResponse;
        });
    }

    private void handleDetectorFailure(final BulkResponse bulkResponse, final StreamingDetectorMetadata streamingDetector,
                                       final Exception exception) {
        final String detectorName = streamingDetector.getDetectorName();
        log.error("Failed to run detector with name {}", detectorName, exception);
        final String failureMessage = String.format("Failed to run detector with name %s due to %s.", detectorName, exception);

        final List<DocData> failedDocData = streamingDetector.getIndexToDocData().values().stream()
                .flatMap(Collection::stream)
                .collect(Collectors.toList());
        failedDocData.forEach(docData -> {
            final BulkItemResponse originalBulkItemResponse = bulkResponse.getItems()[docData.getBulkItemResponseIndex()];
            final BulkItemResponse recreatedBulkItemResponse = recreateBulkItemResponseWithFailure(originalBulkItemResponse, failureMessage);
            bulkResponse.getItems()[docData.getBulkItemResponseIndex()] = recreatedBulkItemResponse;
        });
    }

    private BulkItemResponse recreateBulkItemResponseWithFailure(final BulkItemResponse originalBulkItemResponse,
                                                                 final String currentFailureMessage) {
        final String index;
        final String docId;
        final String failureMessage;

        // If a previous failure occurred for this document, the BulkItemResponse will already have a Failure entry
        if (originalBulkItemResponse.isFailed()) {
            index = originalBulkItemResponse.getFailure().getIndex();
            docId = originalBulkItemResponse.getFailure().getId();
            failureMessage = originalBulkItemResponse.getFailure().getCause().getMessage() + " " + currentFailureMessage;
        } else {
            index = originalBulkItemResponse.getResponse().getIndex();
            docId = originalBulkItemResponse.getResponse().getId();
            failureMessage = currentFailureMessage;
        }

        final SecurityAnalyticsException failureException = new SecurityAnalyticsException(failureMessage, RestStatus.FAILED_DEPENDENCY, null);
        final BulkItemResponse.Failure failure = new BulkItemResponse.Failure(index, docId, failureException, RestStatus.FAILED_DEPENDENCY);
        return new BulkItemResponse(originalBulkItemResponse.getItemId(), originalBulkItemResponse.getOpType(), failure);
    }

    private void logDuration(final long startTime, final String operation) {
        final long took = System.currentTimeMillis() - startTime;
        log.debug("PERF_DEBUG_STREAMING_SAP: operation [{}] took {} millis", operation, took);
    }
}
