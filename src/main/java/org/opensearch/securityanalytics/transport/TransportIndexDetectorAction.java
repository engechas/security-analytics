/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.search.join.ScoreMode;
import org.apache.lucene.util.SetOnce;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.ActionListener;
import org.opensearch.action.ActionRunnable;
import org.opensearch.action.StepListener;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.GroupedActionListener;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.Client;
import org.opensearch.client.node.NodeClient;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.metadata.MappingMetadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.io.stream.NamedWriteableRegistry;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.LoggingDeprecationHandler;
import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.common.xcontent.ToXContent;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.XContentParser;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.commons.alerting.AlertingPluginInterface;
import org.opensearch.commons.alerting.action.DeleteMonitorRequest;
import org.opensearch.commons.alerting.action.DeleteMonitorResponse;
import org.opensearch.commons.alerting.action.IndexMonitorRequest;
import org.opensearch.commons.alerting.action.IndexMonitorResponse;
import org.opensearch.commons.alerting.model.BucketLevelTrigger;
import org.opensearch.commons.alerting.model.DataSources;
import org.opensearch.commons.alerting.model.DocLevelMonitorInput;
import org.opensearch.commons.alerting.model.DocLevelQuery;
import org.opensearch.commons.alerting.model.DocumentLevelTrigger;
import org.opensearch.commons.alerting.model.Monitor;
import org.opensearch.commons.alerting.model.Monitor.MonitorType;
import org.opensearch.commons.alerting.model.SearchInput;
import org.opensearch.commons.alerting.model.action.Action;
import org.opensearch.commons.authuser.User;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.index.query.QueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.query.RangeQueryBuilder;
import org.opensearch.index.reindex.BulkByScrollResponse;
import org.opensearch.index.seqno.SequenceNumbers;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.rest.RestStatus;
import org.opensearch.script.Script;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.securityanalytics.action.GetIndexMappingsAction;
import org.opensearch.securityanalytics.action.GetIndexMappingsRequest;
import org.opensearch.securityanalytics.action.GetIndexMappingsResponse;
import org.opensearch.securityanalytics.action.IndexDetectorAction;
import org.opensearch.securityanalytics.action.IndexDetectorRequest;
import org.opensearch.securityanalytics.action.IndexDetectorResponse;
import org.opensearch.securityanalytics.config.monitors.DetectorMonitorConfig;
import org.opensearch.securityanalytics.mapper.MapperService;
import org.opensearch.securityanalytics.mapper.MapperUtils;
import org.opensearch.securityanalytics.model.Detector;
import org.opensearch.securityanalytics.model.DetectorInput;
import org.opensearch.securityanalytics.model.DetectorRule;
import org.opensearch.securityanalytics.model.DetectorTrigger;
import org.opensearch.securityanalytics.model.Rule;
import org.opensearch.securityanalytics.model.Value;
import org.opensearch.securityanalytics.rules.backend.OSQueryBackend;
import org.opensearch.securityanalytics.rules.backend.OSQueryBackend.AggregationQueries;
import org.opensearch.securityanalytics.rules.backend.QueryBackend;
import org.opensearch.securityanalytics.rules.exceptions.SigmaError;
import org.opensearch.securityanalytics.settings.SecurityAnalyticsSettings;
import org.opensearch.securityanalytics.util.DetectorIndices;
import org.opensearch.securityanalytics.util.IndexUtils;
import org.opensearch.securityanalytics.util.RuleIndices;
import org.opensearch.securityanalytics.util.RuleTopicIndices;
import org.opensearch.securityanalytics.util.SecurityAnalyticsException;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

public class TransportIndexDetectorAction extends HandledTransportAction<IndexDetectorRequest, IndexDetectorResponse> implements SecureTransportAction {

    public static final String PLUGIN_OWNER_FIELD = "security_analytics";
    private static final Logger log = LogManager.getLogger(TransportIndexDetectorAction.class);
    public static final String TIMESTAMP_FIELD_ALIAS = "timestamp";

    private final Client client;

    private final NamedXContentRegistry xContentRegistry;

    private final DetectorIndices detectorIndices;

    private final RuleTopicIndices ruleTopicIndices;

    private final RuleIndices ruleIndices;

    private final MapperService mapperService;

    private final ClusterService clusterService;

    private final ThreadPool threadPool;

    private volatile Boolean filterByEnabled;


    private final Settings settings;

    private final NamedWriteableRegistry namedWriteableRegistry;

    private final IndexNameExpressionResolver indexNameExpressionResolver;

    private volatile TimeValue indexTimeout;
    @Inject
    public TransportIndexDetectorAction(TransportService transportService,
                                        Client client,
                                        ActionFilters actionFilters,
                                        NamedXContentRegistry xContentRegistry,
                                        DetectorIndices detectorIndices,
                                        RuleTopicIndices ruleTopicIndices,
                                        RuleIndices ruleIndices,
                                        MapperService mapperService,
                                        ClusterService clusterService,
                                        Settings settings,
                                        NamedWriteableRegistry namedWriteableRegistry,
                                        IndexNameExpressionResolver indexNameExpressionResolver) {
        super(IndexDetectorAction.NAME, transportService, actionFilters, IndexDetectorRequest::new);
        this.client = client;
        this.xContentRegistry = xContentRegistry;
        this.detectorIndices = detectorIndices;
        this.ruleTopicIndices = ruleTopicIndices;
        this.ruleIndices = ruleIndices;
        this.mapperService = mapperService;
        this.clusterService = clusterService;
        this.settings = settings;
        this.namedWriteableRegistry = namedWriteableRegistry;
        this.indexNameExpressionResolver = indexNameExpressionResolver;
        this.threadPool = this.detectorIndices.getThreadPool();
        this.indexTimeout = SecurityAnalyticsSettings.INDEX_TIMEOUT.get(this.settings);
        this.filterByEnabled = SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES.get(this.settings);

        this.clusterService.getClusterSettings().addSettingsUpdateConsumer(SecurityAnalyticsSettings.FILTER_BY_BACKEND_ROLES, this::setFilterByEnabled);

    }

    @Override
    protected void doExecute(Task task, IndexDetectorRequest request, ActionListener<IndexDetectorResponse> listener) {
        User user = readUserFromThreadContext(this.threadPool);

        String validateBackendRoleMessage = validateUserBackendRoles(user, this.filterByEnabled);
        if (!"".equals(validateBackendRoleMessage)) {
            listener.onFailure(SecurityAnalyticsException.wrap(new OpenSearchStatusException(validateBackendRoleMessage, RestStatus.FORBIDDEN)));
            return;
        }

        checkIndicesAndExecute(task, request, listener, user);
    }

    private void checkIndicesAndExecute(
        Task task,
        IndexDetectorRequest request,
        ActionListener<IndexDetectorResponse> listener,
        User user
    ) {
        log.debug("check indices and execute began");
        String [] detectorIndices = request.getDetector().getInputs().stream().flatMap(detectorInput -> detectorInput.getIndices().stream()).toArray(String[]::new);
        SearchRequest searchRequest =  new SearchRequest(detectorIndices).source(SearchSourceBuilder.searchSource().size(1).query(QueryBuilders.matchAllQuery()));
        searchRequest.setCancelAfterTimeInterval(TimeValue.timeValueSeconds(30));
        client.search(searchRequest, new ActionListener<>() {
            @Override
            public void onResponse(SearchResponse searchResponse) {
                log.debug("check indices and execute completed. Took {} millis", searchResponse.getTook().millis());
                AsyncIndexDetectorsAction asyncAction = new AsyncIndexDetectorsAction(user, task, request, listener);
                asyncAction.start();
            }

            @Override
            public void onFailure(Exception e) {
                log.debug("check indices and execute failed", e);
                if (e instanceof OpenSearchStatusException) {
                    listener.onFailure(SecurityAnalyticsException.wrap(
                        new OpenSearchStatusException(String.format(Locale.getDefault(), "User doesn't have read permissions for one or more configured index %s", detectorIndices), RestStatus.FORBIDDEN)
                    ));
                } else if (e instanceof IndexNotFoundException) {
                    listener.onFailure(SecurityAnalyticsException.wrap(
                            new OpenSearchStatusException(String.format(Locale.getDefault(), "Indices not found %s", String.join(", ", detectorIndices)), RestStatus.NOT_FOUND)
                    ));
                }
                else {
                    listener.onFailure(SecurityAnalyticsException.wrap(e));
                }
            }
        });
    }

    private void createMonitorFromQueries(String index, List<Pair<String, Rule>> rulesById, Detector detector, ActionListener<List<IndexMonitorResponse>> listener, WriteRequest.RefreshPolicy refreshPolicy,
                                          List<String> queryFieldNames) {
        List<Pair<String, Rule>> docLevelRules = rulesById.stream().filter(it -> !it.getRight().isAggregationRule()).collect(
            Collectors.toList());
        List<Pair<String, Rule>> bucketLevelRules = rulesById.stream().filter(it -> it.getRight().isAggregationRule()).collect(
            Collectors.toList());

        try {
            List<IndexMonitorRequest> monitorRequests = new ArrayList<>();

            if (!docLevelRules.isEmpty()) {
                monitorRequests.add(createDocLevelMonitorRequest(Pair.of(index, docLevelRules), detector, refreshPolicy, Monitor.NO_ID, Method.POST, queryFieldNames));
            }
            if (!bucketLevelRules.isEmpty()) {
                StepListener<List<IndexMonitorRequest>> bucketLevelMonitorRequests = new StepListener<>();
                buildBucketLevelMonitorRequests(Pair.of(index, bucketLevelRules), detector, refreshPolicy, Monitor.NO_ID, Method.POST, bucketLevelMonitorRequests);
                bucketLevelMonitorRequests.whenComplete(indexMonitorRequests -> {
                    log.debug("bucket level monitor request built");
                    monitorRequests.addAll(indexMonitorRequests);

                    // Do nothing if detector doesn't have any monitor
                    if (monitorRequests.isEmpty()) {
                        listener.onResponse(Collections.emptyList());
                        return;
                    }

                    List<IndexMonitorResponse> monitorResponses = new ArrayList<>();
                    StepListener<IndexMonitorResponse> addFirstMonitorStep = new StepListener();

                    // Indexing monitors in two steps in order to prevent all shards failed error from alerting
                    // https://github.com/opensearch-project/alerting/issues/646
                    AlertingPluginInterface.INSTANCE.indexMonitor((NodeClient) client, monitorRequests.get(0), namedWriteableRegistry, addFirstMonitorStep);
                    addFirstMonitorStep.whenComplete(addedFirstMonitorResponse -> {
                        log.debug("first monitor created id {} of type {}", addedFirstMonitorResponse.getId(), addedFirstMonitorResponse.getMonitor().getMonitorType());
                        monitorResponses.add(addedFirstMonitorResponse);
                        int numberOfUnprocessedResponses = monitorRequests.size() - 1;
                        if (numberOfUnprocessedResponses == 0) {
                            listener.onResponse(monitorResponses);
                        } else {
                            saveMonitors(monitorRequests, monitorResponses, numberOfUnprocessedResponses, listener);
                        }
                    }, listener::onFailure);
                }, listener::onFailure);
            } else {
                // Failure if detector doesn't have any monitor
                if (monitorRequests.isEmpty()) {
                    listener.onFailure(new OpenSearchStatusException("Detector cannot be created as no compatible rules were provided", RestStatus.BAD_REQUEST));
                    return;
                }
                List<IndexMonitorResponse> monitorResponses = new ArrayList<>();
                StepListener<IndexMonitorResponse> indexDocLevelMonitorStep = new StepListener();
                // Indexing monitors in two steps in order to prevent all shards failed error from alerting
                // https://github.com/opensearch-project/alerting/issues/646
                AlertingPluginInterface.INSTANCE.indexMonitor((NodeClient) client, monitorRequests.get(0), namedWriteableRegistry, indexDocLevelMonitorStep);
                indexDocLevelMonitorStep.whenComplete(addedFirstMonitorResponse -> {
                    log.debug("first monitor created id {} of type {}", addedFirstMonitorResponse.getId(), addedFirstMonitorResponse.getMonitor().getMonitorType());
                    monitorResponses.add(addedFirstMonitorResponse);
                    int numberOfUnprocessedResponses = monitorRequests.size() - 1;
                    if (numberOfUnprocessedResponses == 0) {
                        listener.onResponse(monitorResponses);
                    } else {
                        saveMonitors(monitorRequests, monitorResponses, numberOfUnprocessedResponses, listener);
                    }
                }, listener::onFailure);
            }
        } catch (Exception ex) {
            listener.onFailure(ex);
        }
    }

    private void saveMonitors(
            List<IndexMonitorRequest> monitorRequests,
            List<IndexMonitorResponse> monitorResponses,
            int numberOfUnprocessedResponses,
            ActionListener<List<IndexMonitorResponse>> listener
    ) {
        GroupedActionListener<IndexMonitorResponse> monitorResponseListener = new GroupedActionListener(
                new ActionListener<Collection<IndexMonitorResponse>>() {
                    @Override
                    public void onResponse(Collection<IndexMonitorResponse> indexMonitorResponses) {
                        monitorResponses.addAll(indexMonitorResponses.stream().collect(Collectors.toList()));
                        listener.onResponse(monitorResponses);
                    }
                    @Override
                    public void onFailure(Exception e) {
                        listener.onFailure(e);
                    }
                }, numberOfUnprocessedResponses);
        for (int i = 1; i < monitorRequests.size(); i++) {
            AlertingPluginInterface.INSTANCE.indexMonitor((NodeClient) client, monitorRequests.get(i), namedWriteableRegistry, monitorResponseListener);
        }
    }

    private void updateMonitorFromQueries(String index, List<Pair<String, Rule>> rulesById, Detector detector, ActionListener<List<IndexMonitorResponse>> listener, WriteRequest.RefreshPolicy refreshPolicy,
                                          List<String> queryFieldNames) throws IOException {
        List<IndexMonitorRequest> monitorsToBeUpdated = new ArrayList<>();

        List<Pair<String, Rule>> bucketLevelRules = rulesById.stream().filter(it -> it.getRight().isAggregationRule()).collect(
            Collectors.toList());
        List<IndexMonitorRequest> monitorsToBeAdded = new ArrayList<>();
        // Process bucket level monitors
        if (!bucketLevelRules.isEmpty()) {
            List<String> ruleCategories = bucketLevelRules.stream().map(Pair::getRight).map(Rule::getCategory).distinct().collect(
                Collectors.toList());
            Map<String, QueryBackend> queryBackendMap = new HashMap<>();
            for(String category: ruleCategories){
                queryBackendMap.put(category, new OSQueryBackend(category, true, true));
            }

            // Pair of RuleId - MonitorId for existing monitors of the detector
            Map<String, String> monitorPerRule = detector.getRuleIdMonitorIdMap();
            GroupedActionListener<IndexMonitorRequest> groupedActionListener = new GroupedActionListener<>(
                    new ActionListener<>() {
                        @Override
                        public void onResponse(Collection<IndexMonitorRequest> indexMonitorRequests) {
                            onIndexMonitorRequestCreation(
                                    index,
                                    monitorsToBeUpdated,
                                    monitorsToBeAdded,
                                    rulesById,
                                    detector,
                                    refreshPolicy,
                                    queryFieldNames,
                                    listener
                            );
                        }

                        @Override
                        public void onFailure(Exception e) {
                            listener.onFailure(e);
                        }
                    }, bucketLevelRules.size()
            );

            for (Pair<String, Rule> query: bucketLevelRules) {
                Rule rule = query.getRight();
                if (rule.getAggregationQueries() != null){
                    // Detect if the monitor should be added or updated
                    if (monitorPerRule.containsKey(rule.getId())) {
                        String monitorId = monitorPerRule.get(rule.getId());
                        createBucketLevelMonitorRequest(query.getRight(),
                            index,
                            detector,
                            refreshPolicy,
                            monitorId,
                            Method.PUT,
                            queryBackendMap.get(rule.getCategory()),
                                new ActionListener<>() {
                                    @Override
                                    public void onResponse(IndexMonitorRequest indexMonitorRequest) {
                                        monitorsToBeUpdated.add(indexMonitorRequest);
                                        groupedActionListener.onResponse(indexMonitorRequest);
                                    }

                                    @Override
                                    public void onFailure(Exception e) {
                                        log.error("Failed to create bucket level monitor request", e);
                                        listener.onFailure(e);
                                    }

                                });
                    } else {
                        createBucketLevelMonitorRequest(query.getRight(),
                            index,
                            detector,
                            refreshPolicy,
                            Monitor.NO_ID,
                            Method.POST,
                            queryBackendMap.get(rule.getCategory()),
                                new ActionListener<>() {
                                    @Override
                                    public void onResponse(IndexMonitorRequest indexMonitorRequest) {
                                        monitorsToBeAdded.add(indexMonitorRequest);
                                        groupedActionListener.onResponse(indexMonitorRequest);
                                    }

                                    @Override
                                    public void onFailure(Exception e) {
                                        log.error("Failed to create bucket level monitor request", e);
                                        listener.onFailure(e);
                                    }
                                });
                    }
                }
            }
        }
    }

    private void onIndexMonitorRequestCreation(String index,
                                               List<IndexMonitorRequest> monitorsToBeUpdated,
                                               List<IndexMonitorRequest> monitorsToBeAdded,
                                               List<Pair<String, Rule>> rulesById,
                                               Detector detector,
                                               RefreshPolicy refreshPolicy,
                                               List<String> queryFieldNames,
                                               ActionListener<List<IndexMonitorResponse>> listener) {
        List<Pair<String, Rule>> docLevelRules = rulesById.stream().filter(it -> !it.getRight().isAggregationRule()).collect(
                Collectors.toList());

        // Process doc level monitors
        if (!docLevelRules.isEmpty()) {
            if (detector.getDocLevelMonitorId() == null) {
                monitorsToBeAdded.add(createDocLevelMonitorRequest(Pair.of(index, docLevelRules), detector, refreshPolicy, Monitor.NO_ID, Method.POST, queryFieldNames));
            } else {
                monitorsToBeUpdated.add(createDocLevelMonitorRequest(Pair.of(index, docLevelRules), detector, refreshPolicy, detector.getDocLevelMonitorId(), Method.PUT, queryFieldNames));
            }
        }

        List<String> monitorIdsToBeDeleted = detector.getRuleIdMonitorIdMap().values().stream().collect(Collectors.toList());
        monitorIdsToBeDeleted.removeAll(monitorsToBeUpdated.stream().map(IndexMonitorRequest::getMonitorId).collect(
                Collectors.toList()));

        updateAlertingMonitors(monitorsToBeAdded, monitorsToBeUpdated, monitorIdsToBeDeleted, refreshPolicy, listener);
    }

    /**
     *  Update list of monitors for the given detector
     *  Executed in a steps:
     *  1. Add new monitors;
     *  2. Update existing monitors;
     *  3. Delete the monitors omitted from request
     *  4. Respond with updated list of monitors
     * @param monitorsToBeAdded Newly added monitors by the user
     * @param monitorsToBeUpdated Existing monitors that will be updated
     * @param monitorsToBeDeleted Monitors omitted by the user
     * @param refreshPolicy
     * @param listener Listener that accepts the list of updated monitors if the action was successful
     */
    private void updateAlertingMonitors(
        List<IndexMonitorRequest> monitorsToBeAdded,
        List<IndexMonitorRequest> monitorsToBeUpdated,
        List<String> monitorsToBeDeleted,
        RefreshPolicy refreshPolicy,
        ActionListener<List<IndexMonitorResponse>> listener
    ) {
        List<IndexMonitorResponse> updatedMonitors = new ArrayList<>();

        // Update monitor steps
        StepListener<List<IndexMonitorResponse>> addNewMonitorsStep = new StepListener();
        executeMonitorActionRequest(monitorsToBeAdded, addNewMonitorsStep);
        // 1. Add new alerting monitors (for the rules that didn't exist previously)
        addNewMonitorsStep.whenComplete(addNewMonitorsResponse -> {
            if (addNewMonitorsResponse != null && !addNewMonitorsResponse.isEmpty()) {
                updatedMonitors.addAll(addNewMonitorsResponse);
            }

            StepListener<List<IndexMonitorResponse>> updateMonitorsStep = new StepListener<>();
            executeMonitorActionRequest(monitorsToBeUpdated, updateMonitorsStep);
            // 2. Update existing alerting monitors (based on the common rules)
            updateMonitorsStep.whenComplete(updateMonitorResponse -> {
                if (updateMonitorResponse!=null && !updateMonitorResponse.isEmpty()) {
                    updatedMonitors.addAll(updateMonitorResponse);
                }

                    StepListener<List<DeleteMonitorResponse>> deleteMonitorStep = new StepListener<>();
                    deleteAlertingMonitors(monitorsToBeDeleted, refreshPolicy, deleteMonitorStep);
                    // 3. Delete alerting monitors (rules that are not provided by the user)
                    deleteMonitorStep.whenComplete(deleteMonitorResponses ->
                            // Return list of all updated + newly added monitors
                            listener.onResponse(updatedMonitors),
                        // Handle delete monitors (step 3)
                        listener::onFailure);
                }, // Handle update monitor failed (step 2)
                listener::onFailure);
            // Handle add failed (step 1)
        }, listener::onFailure);
    }

    private IndexMonitorRequest createDocLevelMonitorRequest(Pair<String, List<Pair<String, Rule>>> logIndexToQueries, Detector detector,
                                                             WriteRequest.RefreshPolicy refreshPolicy, String monitorId, RestRequest.Method restMethod, List<String> queryFieldNames) {
        List<DocLevelMonitorInput> docLevelMonitorInputs = new ArrayList<>();

        List<DocLevelQuery> docLevelQueries = new ArrayList<>();

        for (Pair<String, Rule> query: logIndexToQueries.getRight()) {
            String id = query.getLeft();

            Rule rule = query.getRight();
            String name = query.getLeft();

            String actualQuery = rule.getQueries().get(0).getValue();

            List<String> tags = new ArrayList<>();
            tags.add(rule.getLevel());
            tags.add(rule.getCategory());
            tags.addAll(rule.getTags().stream().map(Value::getValue).collect(Collectors.toList()));

            DocLevelQuery docLevelQuery = new DocLevelQuery(id, name, actualQuery, tags, queryFieldNames);
            docLevelQueries.add(docLevelQuery);
        }
        DocLevelMonitorInput docLevelMonitorInput = new DocLevelMonitorInput(detector.getName(), List.of(logIndexToQueries.getKey()), docLevelQueries);
        docLevelMonitorInputs.add(docLevelMonitorInput);

        List<DocumentLevelTrigger> triggers = new ArrayList<>();
        List<DetectorTrigger> detectorTriggers = detector.getTriggers();

        for (DetectorTrigger detectorTrigger: detectorTriggers) {
            String id = detectorTrigger.getId();
            String name = detectorTrigger.getName();
            String severity = detectorTrigger.getSeverity();
            List<Action> actions = detectorTrigger.getActions();
            Script condition = detectorTrigger.convertToCondition();

            triggers.add(new DocumentLevelTrigger(id, name, severity, actions, condition));
        }

        Monitor monitor = new Monitor(monitorId, Monitor.NO_VERSION, detector.getName(), detector.getEnabled(), detector.getSchedule(), detector.getLastUpdateTime(), detector.getEnabledTime(),
            Monitor.MonitorType.DOC_LEVEL_MONITOR, detector.getUser(), 1, docLevelMonitorInputs, triggers, Map.of(),
            new DataSources(detector.getRuleIndex(),
                detector.getFindingsIndex(),
                detector.getFindingsIndexPattern(),
                detector.getAlertsIndex(),
                detector.getAlertsHistoryIndex(),
                detector.getAlertsHistoryIndexPattern(),
                DetectorMonitorConfig.getRuleIndexMappingsByType(detector.getDetectorType()),
                true), PLUGIN_OWNER_FIELD);

        return new IndexMonitorRequest(monitorId, SequenceNumbers.UNASSIGNED_SEQ_NO, SequenceNumbers.UNASSIGNED_PRIMARY_TERM, refreshPolicy, restMethod, monitor, null);
    }

    private void buildBucketLevelMonitorRequests(Pair<String, List<Pair<String, Rule>>> logIndexToQueries, Detector detector,
                                                 WriteRequest.RefreshPolicy refreshPolicy, String monitorId, RestRequest.Method restMethod,
                                                 ActionListener<List<IndexMonitorRequest>> listener) {
        log.debug("bucket level monitor request starting");
        log.debug("get rule field mappings request being made");
        List<String> ruleCategories = logIndexToQueries.getRight().stream().map(Pair::getRight).map(Rule::getCategory).distinct().collect(
            Collectors.toList());
        Map<String, QueryBackend> queryBackendMap = new HashMap<>();

        for(String category: ruleCategories){
            try {
                queryBackendMap.put(category, new OSQueryBackend(category, true, true));
            } catch (IOException e) {
                logger.error("Failed to create OSQueryBackend from category", e);
                listener.onFailure(e);
            }
        }

        List<IndexMonitorRequest> monitorRequests = new ArrayList<>();
        GroupedActionListener<IndexMonitorRequest> bucketLevelMonitorRequestsListener = new GroupedActionListener<>(
                new ActionListener<>() {
                    @Override
                    public void onResponse(Collection<IndexMonitorRequest> indexMonitorRequests) {
                        listener.onResponse(monitorRequests);
                    }

                    @Override
                    public void onFailure(Exception e) {
                        listener.onFailure(e);
                    }
                }, logIndexToQueries.getRight().size());

        for (Pair<String, Rule> query: logIndexToQueries.getRight()) {
            Rule rule = query.getRight();

            // Creating bucket level monitor per each aggregation rule
            if (rule.getAggregationQueries() != null) {
                createBucketLevelMonitorRequest(
                    query.getRight(),
                    logIndexToQueries.getLeft(),
                    detector,
                    refreshPolicy,
                    Monitor.NO_ID,
                    Method.POST,
                    queryBackendMap.get(rule.getCategory()),
                        new ActionListener<>() {
                            @Override
                            public void onResponse(IndexMonitorRequest indexMonitorRequest) {
                                monitorRequests.add(indexMonitorRequest);
                                bucketLevelMonitorRequestsListener.onResponse(indexMonitorRequest);
                            }

                            @Override
                            public void onFailure(Exception e) {
                                logger.error("Failed to build bucket level monitor requests", e);
                                bucketLevelMonitorRequestsListener.onFailure(e);
                            }
                        });
            } else {
                log.debug("Aggregation query is null in rule {}", rule.getId());
                bucketLevelMonitorRequestsListener.onResponse(null);
            }
        }
    }

    private void createBucketLevelMonitorRequest(
        Rule rule,
        String index,
        Detector detector,
        WriteRequest.RefreshPolicy refreshPolicy,
        String monitorId,
        RestRequest.Method restMethod,
        QueryBackend queryBackend,
        ActionListener<IndexMonitorRequest> listener
    ) {
        log.debug(":create bucket level monitor response starting");
        try {
            AggregationQueries aggregationQueries = queryBackend.convertAggregation(rule.getAggregationItemsFromRule().get(0));

            SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder()
                    .seqNoAndPrimaryTerm(true)
                    .version(true)
                    // Build query string filter
                    .query(QueryBuilders.queryStringQuery(rule.getQueries().get(0).getValue()))
                    .aggregation(aggregationQueries.getAggBuilder());
            String concreteIndex = IndexUtils.getNewIndexByCreationDate( // index variable in method signature can also be an index pattern
                    clusterService.state(),
                    indexNameExpressionResolver,
                    index
            );

            client.execute(
                    GetIndexMappingsAction.INSTANCE,
                    new GetIndexMappingsRequest(concreteIndex),
                    new ActionListener<>() {
                        @Override
                        public void onResponse(GetIndexMappingsResponse getIndexMappingsResponse) {
                            MappingMetadata mappingMetadata = getIndexMappingsResponse.mappings().get(concreteIndex);
                            List<Pair<String, String>> pairs = null;
                            try {
                                pairs = MapperUtils.getAllAliasPathPairs(mappingMetadata);
                            } catch (IOException e) {
                                logger.debug("Failed to get alias path pairs from mapping metadata", e);
                                onFailure(e);
                            }
                            boolean timeStampAliasPresent = pairs.
                                    stream()
                                    .anyMatch(p ->
                                            TIMESTAMP_FIELD_ALIAS.equals(p.getLeft()) || TIMESTAMP_FIELD_ALIAS.equals(p.getRight()));
                            if(timeStampAliasPresent) {
                                BoolQueryBuilder boolQueryBuilder = searchSourceBuilder.query() == null
                                        ? new BoolQueryBuilder()
                                        : QueryBuilders.boolQuery().must(searchSourceBuilder.query());
                                RangeQueryBuilder timeRangeFilter = QueryBuilders.rangeQuery(TIMESTAMP_FIELD_ALIAS)
                                        .gt("{{period_end}}||-1h")
                                        .lte("{{period_end}}")
                                        .format("epoch_millis");
                                boolQueryBuilder.must(timeRangeFilter);
                                searchSourceBuilder.query(boolQueryBuilder);
                            }

                            List<SearchInput> bucketLevelMonitorInputs = new ArrayList<>();
                            bucketLevelMonitorInputs.add(new SearchInput(Arrays.asList(index), searchSourceBuilder));

                            List<BucketLevelTrigger> triggers = new ArrayList<>();
                            BucketLevelTrigger bucketLevelTrigger = new BucketLevelTrigger(rule.getId(), rule.getTitle(), rule.getLevel(), aggregationQueries.getCondition(),
                                    Collections.emptyList());
                            triggers.add(bucketLevelTrigger);

                            /** TODO - Think how to use detector trigger
                             List<DetectorTrigger> detectorTriggers = detector.getTriggers();
                             for (DetectorTrigger detectorTrigger: detectorTriggers) {
                             String id = detectorTrigger.getId();
                             String name = detectorTrigger.getName();
                             String severity = detectorTrigger.getSeverity();
                             List<Action> actions = detectorTrigger.getActions();
                             Script condition = detectorTrigger.convertToCondition();

                             BucketLevelTrigger bucketLevelTrigger1 = new BucketLevelTrigger(id, name, severity, condition, actions);
                             triggers.add(bucketLevelTrigger1);
                             } **/

                            Monitor monitor = new Monitor(monitorId, Monitor.NO_VERSION, detector.getName(), detector.getEnabled(), detector.getSchedule(), detector.getLastUpdateTime(), detector.getEnabledTime(),
                                    MonitorType.BUCKET_LEVEL_MONITOR, detector.getUser(), 1, bucketLevelMonitorInputs, triggers, Map.of(),
                                    new DataSources(detector.getRuleIndex(),
                                            detector.getFindingsIndex(),
                                            detector.getFindingsIndexPattern(),
                                            detector.getAlertsIndex(),
                                            detector.getAlertsHistoryIndex(),
                                            detector.getAlertsHistoryIndexPattern(),
                                            DetectorMonitorConfig.getRuleIndexMappingsByType(detector.getDetectorType()),
                                            true), PLUGIN_OWNER_FIELD);

                            listener.onResponse(new IndexMonitorRequest(monitorId, SequenceNumbers.UNASSIGNED_SEQ_NO, SequenceNumbers.UNASSIGNED_PRIMARY_TERM, refreshPolicy, restMethod, monitor, null));
                        }

                        @Override
                        public void onFailure(Exception e) {
                            log.error(
                                    String.format(Locale.getDefault(),
                                            "Unable to verify presence of timestamp alias for index [%s] in detector [%s]. Not setting time range filter for bucket level monitor.",
                                            concreteIndex, detector.getName()), e);
                            listener.onFailure(e);
                        }
                    });
        } catch (SigmaError e) {
            log.error("Failed to create bucket level monitor request", e);
            listener.onFailure(e);
        }
    }

    /**
     * Executes monitor related requests (PUT/POST) - returns the response once all the executions are completed
     * @param indexMonitors  Monitors to be updated/added
     * @param listener actionListener for handling updating/creating monitors
     */
    public void executeMonitorActionRequest(
        List<IndexMonitorRequest> indexMonitors,
        ActionListener<List<IndexMonitorResponse>> listener) {

        // In the case of not provided monitors, just return empty list
        if (indexMonitors == null || indexMonitors.isEmpty()) {
            listener.onResponse(new ArrayList<>());
            return;
        }

        GroupedActionListener<IndexMonitorResponse> monitorResponseListener = new GroupedActionListener(
            new ActionListener<Collection<IndexMonitorResponse>>() {
                @Override
                public void onResponse(Collection<IndexMonitorResponse> indexMonitorResponse) {
                    listener.onResponse(indexMonitorResponse.stream().collect(Collectors.toList()));
                }
                @Override
                public void onFailure(Exception e) {
                    listener.onFailure(e);
                }
            }, indexMonitors.size());

        // Persist monitors sequentially
        for (IndexMonitorRequest req: indexMonitors) {
            AlertingPluginInterface.INSTANCE.indexMonitor((NodeClient) client, req, namedWriteableRegistry, monitorResponseListener);
        }
    }

    /**
     * Deletes the alerting monitors based on the given ids and notifies the listener that will be notified once all monitors have been deleted
     * @param monitorIds monitor ids to be deleted
     * @param refreshPolicy
     * @param listener listener that will be notified once all the monitors are being deleted
     */
    private void deleteAlertingMonitors(List<String> monitorIds, WriteRequest.RefreshPolicy refreshPolicy, ActionListener<List<DeleteMonitorResponse>> listener){
        if (monitorIds == null || monitorIds.isEmpty()) {
            listener.onResponse(new ArrayList<>());
            return;
        }
        ActionListener<DeleteMonitorResponse> deletesListener = new GroupedActionListener<>(new ActionListener<>() {
            @Override
            public void onResponse(Collection<DeleteMonitorResponse> responses) {
                SetOnce<RestStatus> errorStatusSupplier = new SetOnce<>();
                if (responses.stream().filter(response -> {
                    if (response.getStatus() != RestStatus.OK) {
                        log.error("Monitor [{}] could not be deleted. Status [{}]", response.getId(), response.getStatus());
                        errorStatusSupplier.trySet(response.getStatus());
                        return true;
                    }
                    return false;
                }).count() > 0) {
                    listener.onFailure(new OpenSearchStatusException("Monitor associated with detected could not be deleted", errorStatusSupplier.get()));
                }
                listener.onResponse(responses.stream().collect(Collectors.toList()));
            }
            @Override
            public void onFailure(Exception e) {
                listener.onFailure(e);
            }
        }, monitorIds.size());

        for (String monitorId : monitorIds) {
            deleteAlertingMonitor(monitorId, refreshPolicy, deletesListener);
        }
    }
    private void deleteAlertingMonitor(String monitorId, WriteRequest.RefreshPolicy refreshPolicy, ActionListener<DeleteMonitorResponse> listener) {
        DeleteMonitorRequest request = new DeleteMonitorRequest(monitorId, refreshPolicy);
        AlertingPluginInterface.INSTANCE.deleteMonitor((NodeClient) client, request, listener);
    }

    private void onCreateMappingsResponse(CreateIndexResponse response) throws IOException {
        if (response.isAcknowledged()) {
            log.info(String.format(Locale.getDefault(), "Created %s with mappings.", Detector.DETECTORS_INDEX));
            IndexUtils.detectorIndexUpdated();
        } else {
            log.error(String.format(Locale.getDefault(), "Create %s mappings call not acknowledged.", Detector.DETECTORS_INDEX));
            throw new OpenSearchStatusException(String.format(Locale.getDefault(), "Create %s mappings call not acknowledged", Detector.DETECTORS_INDEX), RestStatus.INTERNAL_SERVER_ERROR);
        }
    }

    private void onUpdateMappingsResponse(AcknowledgedResponse response) {
        if (response.isAcknowledged()) {
            log.info(String.format(Locale.getDefault(), "Updated  %s with mappings.", Detector.DETECTORS_INDEX));
            IndexUtils.detectorIndexUpdated();
        } else {
            log.error(String.format(Locale.getDefault(), "Update %s mappings call not acknowledged.", Detector.DETECTORS_INDEX));
            throw new OpenSearchStatusException(String.format(Locale.getDefault(), "Update %s mappings call not acknowledged.", Detector.DETECTORS_INDEX), RestStatus.INTERNAL_SERVER_ERROR);
        }
    }

    class AsyncIndexDetectorsAction {
        private final IndexDetectorRequest request;

        private final ActionListener<IndexDetectorResponse> listener;
        private final AtomicReference<Object> response;
        private final AtomicBoolean counter = new AtomicBoolean();
        private final Task task;
        private final User user;

        AsyncIndexDetectorsAction(User user, Task task, IndexDetectorRequest request, ActionListener<IndexDetectorResponse> listener) {
            this.task = task;
            this.request = request;
            this.listener = listener;
            this.user = user;

            this.response = new AtomicReference<>();
        }

        void start() {
            log.debug("stash context");
            try {
                TransportIndexDetectorAction.this.threadPool.getThreadContext().stashContext();
                log.debug("log type check : {}", request.getDetector().getDetectorType());

                if (!detectorIndices.detectorIndexExists()) {
                    log.debug("detector index creation");
                    detectorIndices.initDetectorIndex(new ActionListener<>() {
                        @Override
                        public void onResponse(CreateIndexResponse response) {
                            log.debug("detector index created in {}");
                            try {
                                onCreateMappingsResponse(response);
                                prepareDetectorIndexing();
                            } catch (IOException e) {
                                log.debug("detector index creation failed", e);
                                onFailures(e);
                            }
                        }

                        @Override
                        public void onFailure(Exception e) {
                            onFailures(e);
                        }
                    });
                } else if (!IndexUtils.detectorIndexUpdated) {
                    log.debug("detector index update mapping");
                    IndexUtils.updateIndexMapping(
                            Detector.DETECTORS_INDEX,
                            DetectorIndices.detectorMappings(), clusterService.state(), client.admin().indices(),
                            new ActionListener<>() {
                                @Override
                                public void onResponse(AcknowledgedResponse response) {
                                    log.debug("detector index mapping updated");
                                    onUpdateMappingsResponse(response);
                                    try {
                                        prepareDetectorIndexing();
                                    } catch (IOException e) {
                                        log.debug("detector index mapping FAILED updation", e);
                                        onFailures(e);
                                    }
                                }

                                @Override
                                public void onFailure(Exception e) {
                                    onFailures(e);
                                }
                            }
                    );
                } else {
                    prepareDetectorIndexing();
                }
            } catch (IOException e) {
                onFailures(e);
            }
        }

        void prepareDetectorIndexing() throws IOException {
            if (request.getMethod() == RestRequest.Method.POST) {
                createDetector();
            } else if (request.getMethod() == RestRequest.Method.PUT) {
                updateDetector();
            }
        }

        void createDetector() {
            Detector detector = request.getDetector();
            String ruleTopic = detector.getDetectorType();

            request.getDetector().setAlertsIndex(DetectorMonitorConfig.getAlertsIndex(ruleTopic));
            request.getDetector().setAlertsHistoryIndex(DetectorMonitorConfig.getAlertsHistoryIndex(ruleTopic));
            request.getDetector().setAlertsHistoryIndexPattern(DetectorMonitorConfig.getAlertsHistoryIndexPattern(ruleTopic));
            request.getDetector().setFindingsIndex(DetectorMonitorConfig.getFindingsIndex(ruleTopic));
            request.getDetector().setFindingsIndexPattern(DetectorMonitorConfig.getFindingsIndexPattern(ruleTopic));
            request.getDetector().setRuleIndex(DetectorMonitorConfig.getRuleIndex(ruleTopic));

            User originalContextUser = this.user;
            log.debug("user from original context is {}", originalContextUser);
            request.getDetector().setUser(originalContextUser);


            if (!detector.getInputs().isEmpty()) {
                try {
                    log.debug("init rule index template");
                    ruleTopicIndices.initRuleTopicIndexTemplate(new ActionListener<>() {
                        @Override
                        public void onResponse(AcknowledgedResponse acknowledgedResponse) {
                            log.debug("init rule index template ack");

                            initRuleIndexAndImportRules(request, new ActionListener<>() {
                                @Override
                                public void onResponse(List<IndexMonitorResponse> monitorResponses) {
                                    log.debug("monitors indexed");
                                    request.getDetector().setMonitorIds(getMonitorIds(monitorResponses));
                                    request.getDetector().setRuleIdMonitorIdMap(mapMonitorIds(monitorResponses));
                                    try {
                                        indexDetector();
                                    } catch (Exception e) {
                                        logger.debug("create detector failed", e);
                                        onFailures(e);
                                    }
                                }

                                @Override
                                public void onFailure(Exception e) {
                                    logger.debug("import rules failed", e);
                                    onFailures(e);
                                }
                            });
                        }

                        @Override
                        public void onFailure(Exception e) {
                            logger.debug("init rules index failed", e);
                            onFailures(e);
                        }
                    });
                } catch (Exception e) {
                    logger.debug("init rules index failed", e);
                    onFailures(e);
                }
            }
        }

        void updateDetector() {
            String id = request.getDetectorId();

            User originalContextUser = this.user;
            log.debug("user from original context is {}", originalContextUser);

            GetRequest request = new GetRequest(Detector.DETECTORS_INDEX, id);
            client.get(request, new ActionListener<>() {
                @Override
                public void onResponse(GetResponse response) {
                    if (!response.isExists()) {
                        onFailures(new OpenSearchStatusException(String.format(Locale.getDefault(), "Detector with %s is not found", id), RestStatus.NOT_FOUND));
                        return;
                    }

                    try {
                        XContentParser xcp = XContentHelper.createParser(
                                xContentRegistry, LoggingDeprecationHandler.INSTANCE,
                                response.getSourceAsBytesRef(), XContentType.JSON
                        );

                        Detector detector = Detector.docParse(xcp, response.getId(), response.getVersion());

                        // security is enabled and filterby is enabled
                        if (!checkUserPermissionsWithResource(
                                originalContextUser,
                                detector.getUser(),
                                "detector",
                                detector.getId(),
                                TransportIndexDetectorAction.this.filterByEnabled
                        )

                        ) {
                            onFailure(SecurityAnalyticsException.wrap(new OpenSearchStatusException("Do not have permissions to resource", RestStatus.FORBIDDEN)));
                            return;
                        }
                        onGetResponse(detector, detector.getUser());
                    } catch (IOException e) {
                        onFailures(e);
                    }
                }

                @Override
                public void onFailure(Exception e) {
                    onFailures(e);
                }
            });
        }

        void onGetResponse(Detector currentDetector, User user) {
            if (request.getDetector().getEnabled() && currentDetector.getEnabled()) {
                request.getDetector().setEnabledTime(currentDetector.getEnabledTime());
            }
            request.getDetector().setMonitorIds(currentDetector.getMonitorIds());
            request.getDetector().setRuleIdMonitorIdMap(currentDetector.getRuleIdMonitorIdMap());
            Detector detector = request.getDetector();

            String ruleTopic = detector.getDetectorType();

            log.debug("user in update detector {}", user);


            request.getDetector().setAlertsIndex(DetectorMonitorConfig.getAlertsIndex(ruleTopic));
            request.getDetector().setAlertsHistoryIndex(DetectorMonitorConfig.getAlertsHistoryIndex(ruleTopic));
            request.getDetector().setAlertsHistoryIndexPattern(DetectorMonitorConfig.getAlertsHistoryIndexPattern(ruleTopic));
            request.getDetector().setFindingsIndex(DetectorMonitorConfig.getFindingsIndex(ruleTopic));
            request.getDetector().setFindingsIndexPattern(DetectorMonitorConfig.getFindingsIndexPattern(ruleTopic));
            request.getDetector().setRuleIndex(DetectorMonitorConfig.getRuleIndex(ruleTopic));
            request.getDetector().setUser(user);

            if (!detector.getInputs().isEmpty()) {
                try {
                    ruleTopicIndices.initRuleTopicIndexTemplate(new ActionListener<>() {
                        @Override
                        public void onResponse(AcknowledgedResponse acknowledgedResponse) {
                            initRuleIndexAndImportRules(request, new ActionListener<>() {
                                @Override
                                public void onResponse(List<IndexMonitorResponse> monitorResponses) {
                                    request.getDetector().setMonitorIds(getMonitorIds(monitorResponses));
                                    request.getDetector().setRuleIdMonitorIdMap(mapMonitorIds(monitorResponses));
                                    try {
                                        indexDetector();
                                    } catch (IOException e) {
                                        onFailures(e);
                                    }
                                }

                                @Override
                                public void onFailure(Exception e) {
                                    onFailures(e);
                                }
                            });
                        }

                        @Override
                        public void onFailure(Exception e) {
                            onFailures(e);
                        }
                    });
                } catch (IOException e) {
                    onFailures(e);
                }
            }
        }

        public void initRuleIndexAndImportRules(IndexDetectorRequest request, ActionListener<List<IndexMonitorResponse>> listener) {
            ruleIndices.initPrepackagedRulesIndex(
                    new ActionListener<>() {
                        @Override
                        public void onResponse(CreateIndexResponse response) {
                            log.debug("prepackaged rule index created");
                            ruleIndices.onCreateMappingsResponse(response, true);
                            ruleIndices.importRules(RefreshPolicy.IMMEDIATE, indexTimeout,
                                    new ActionListener<>() {
                                        @Override
                                        public void onResponse(BulkResponse response) {
                                            log.debug("rules imported");
                                            if (!response.hasFailures()) {
                                                importRules(request, listener);
                                            } else {
                                                onFailures(new OpenSearchStatusException(response.buildFailureMessage(), RestStatus.INTERNAL_SERVER_ERROR));
                                            }
                                        }

                                        @Override
                                        public void onFailure(Exception e) {
                                            log.debug("failed to import rules", e);
                                            onFailures(e);
                                        }
                                    });
                        }

                        @Override
                        public void onFailure(Exception e) {
                            onFailures(e);
                        }
                    },
                    new ActionListener<>() {
                        @Override
                        public void onResponse(AcknowledgedResponse response) {
                            ruleIndices.onUpdateMappingsResponse(response, true);
                            ruleIndices.deleteRules(new ActionListener<>() {
                                @Override
                                public void onResponse(BulkByScrollResponse response) {
                                    ruleIndices.importRules(WriteRequest.RefreshPolicy.IMMEDIATE, indexTimeout,
                                            new ActionListener<>() {
                                                @Override
                                                public void onResponse(BulkResponse response) {
                                                    if (!response.hasFailures()) {
                                                        importRules(request, listener);
                                                    } else {
                                                        onFailures(new OpenSearchStatusException(response.buildFailureMessage(), RestStatus.INTERNAL_SERVER_ERROR));
                                                    }
                                                }

                                                @Override
                                                public void onFailure(Exception e) {
                                                    onFailures(e);
                                                }
                                            });
                                }

                                @Override
                                public void onFailure(Exception e) {
                                    onFailures(e);
                                }
                            });
                        }

                        @Override
                        public void onFailure(Exception e) {
                            onFailures(e);
                        }
                    },
                    new ActionListener<>() {
                        @Override
                        public void onResponse(SearchResponse response) {
                            if (response.isTimedOut()) {
                                onFailures(new OpenSearchStatusException(response.toString(), RestStatus.REQUEST_TIMEOUT));
                            }

                            long count = response.getHits().getTotalHits().value;
                            if (count == 0) {
                                ruleIndices.importRules(WriteRequest.RefreshPolicy.IMMEDIATE, indexTimeout,
                                        new ActionListener<>() {
                                            @Override
                                            public void onResponse(BulkResponse response) {
                                                if (!response.hasFailures()) {
                                                    importRules(request, listener);
                                                } else {
                                                    onFailures(new OpenSearchStatusException(response.buildFailureMessage(), RestStatus.INTERNAL_SERVER_ERROR));
                                                }
                                            }

                                            @Override
                                            public void onFailure(Exception e) {
                                                onFailures(e);
                                            }
                                        });
                            } else {
                                importRules(request, listener);
                            }
                        }

                        @Override
                        public void onFailure(Exception e) {
                            onFailures(e);
                        }
                    }
            );
        }

        @SuppressWarnings("unchecked")
        public void importRules(IndexDetectorRequest request, ActionListener<List<IndexMonitorResponse>> listener) {
            final Detector detector = request.getDetector();
            final String ruleTopic = detector.getDetectorType();
            final DetectorInput detectorInput = detector.getInputs().get(0);
            final String logIndex = detectorInput.getIndices().get(0);

            List<String> ruleIds = detectorInput.getPrePackagedRules().stream().map(DetectorRule::getId).collect(Collectors.toList());

            QueryBuilder queryBuilder =
                    QueryBuilders.nestedQuery("rule",
                            QueryBuilders.boolQuery().must(
                                    QueryBuilders.matchQuery("rule.category", ruleTopic)
                            ).must(
                                    QueryBuilders.termsQuery("_id", ruleIds.toArray(new String[]{}))
                            ),
                            ScoreMode.Avg
                    );

            SearchRequest searchRequest = new SearchRequest(Rule.PRE_PACKAGED_RULES_INDEX)
                    .source(new SearchSourceBuilder()
                            .seqNoAndPrimaryTerm(true)
                            .version(true)
                            .query(queryBuilder)
                            .size(10000));

            logger.debug("importing prepackaged rules");
            client.search(searchRequest, new ActionListener<>() {
                @Override
                public void onResponse(SearchResponse response) {
                    if (response.isTimedOut()) {
                        onFailures(new OpenSearchStatusException(response.toString(), RestStatus.REQUEST_TIMEOUT));
                    }
                    logger.debug("prepackaged rules fetch success");

                    SearchHits hits = response.getHits();
                    List<Pair<String, Rule>> queries = new ArrayList<>();

                    try {
                        for (SearchHit hit: hits) {
                            XContentParser xcp = XContentType.JSON.xContent().createParser(
                                    xContentRegistry,
                                    LoggingDeprecationHandler.INSTANCE, hit.getSourceAsString()
                            );

                            Rule rule = Rule.docParse(xcp, hit.getId(), hit.getVersion());
                            String id = hit.getId();

                            queries.add(Pair.of(id, rule));
                        }

                        if (ruleIndices.ruleIndexExists(false)) {
                            importCustomRules(detector, detectorInput, queries, listener);
                        } else if (detectorInput.getCustomRules().size() > 0) {
                            onFailures(new OpenSearchStatusException("Custom Rule Index not found", RestStatus.NOT_FOUND));
                        } else {
                            resolveRuleFieldNamesAndUpsertMonitorFromQueries(queries, detector, logIndex, listener);
                        }
                    } catch (Exception e) {
                        logger.debug("failed to fetch prepackaged rules", e);
                        onFailures(e);
                    }
                }

                @Override
                public void onFailure(Exception e) {
                    onFailures(e);
                }
            });
        }

        private void resolveRuleFieldNamesAndUpsertMonitorFromQueries(List<Pair<String, Rule>> queries, Detector detector, String logIndex, ActionListener<List<IndexMonitorResponse>> listener) {
            logger.error("PERF_DEBUG_SAP: Fetching alias path pairs to construct rule_field_names");
            long start = System.currentTimeMillis();
            Set<String> ruleFieldNames = new HashSet<>();

            for (Pair<String, Rule> query : queries) {
                List<String> queryFieldNames = query.getValue().getQueryFieldNames().stream().map(Value::getValue).collect(Collectors.toList());
                ruleFieldNames.addAll(queryFieldNames);
            }
            client.execute(GetIndexMappingsAction.INSTANCE, new GetIndexMappingsRequest(logIndex), new ActionListener<>() {
                @Override
                public void onResponse(GetIndexMappingsResponse getMappingsViewResponse) {
                    try {
                        List<Pair<String, String>> aliasPathPairs;

                        aliasPathPairs = MapperUtils.getAllAliasPathPairs(getMappingsViewResponse.getMappings().get(logIndex));
                        for (Pair<String, String> aliasPathPair : aliasPathPairs) {
                            if (ruleFieldNames.contains(aliasPathPair.getLeft())) {
                                ruleFieldNames.remove(aliasPathPair.getLeft());
                                ruleFieldNames.add(aliasPathPair.getRight());
                            }
                        }
                        long took = System.currentTimeMillis() - start;
                        log.debug("completed collecting rule_field_names in {} millis", took);
                    } catch (Exception e) {
                        logger.error("Failure in parsing rule field names/aliases while " +
                                detector.getId() == null ? "creating" : "updating" +
                                " detector. Not optimizing detector queries with relevant fields", e);
                        ruleFieldNames.clear();
                    }
                    try {
                        upsertMonitorQueries(queries, detector, listener, ruleFieldNames, logIndex);
                    } catch (Exception e) {
                        log.error("Caught exception upserting monitor queries", e);
                        listener.onFailure(e);
                    }
                }

                @Override
                public void onFailure(Exception e) {
                    log.error("Failed to fetch mappings view response for log index " + logIndex, e);
                    listener.onFailure(e);
                }
            });
        }

        private void upsertMonitorQueries(List<Pair<String, Rule>> queries, Detector detector, ActionListener<List<IndexMonitorResponse>> listener, Set<String> ruleFieldNames, String logIndex) throws SigmaError, IOException {
            if (request.getMethod() == Method.POST) {
                createMonitorFromQueries(logIndex, queries, detector, listener, request.getRefreshPolicy(), new ArrayList<>(ruleFieldNames));
            } else if (request.getMethod() == Method.PUT) {
                updateMonitorFromQueries(logIndex, queries, detector, listener, request.getRefreshPolicy(), new ArrayList<>(ruleFieldNames));
            }
        }

        @SuppressWarnings("unchecked")
        public void importCustomRules(Detector detector, DetectorInput detectorInput, List<Pair<String, Rule>> queries, ActionListener<List<IndexMonitorResponse>> listener) {
            final String logIndex = detectorInput.getIndices().get(0);
            List<String> ruleIds = detectorInput.getCustomRules().stream().map(DetectorRule::getId).collect(Collectors.toList());

            QueryBuilder queryBuilder = QueryBuilders.termsQuery("_id", ruleIds.toArray(new String[]{}));
            SearchRequest searchRequest = new SearchRequest(Rule.CUSTOM_RULES_INDEX)
                    .source(new SearchSourceBuilder()
                            .seqNoAndPrimaryTerm(true)
                            .version(true)
                            .query(queryBuilder)
                            .size(10000));

            logger.debug("importing custom rules");
            client.search(searchRequest, new ActionListener<>() {
                @Override
                public void onResponse(SearchResponse response) {
                    if (response.isTimedOut()) {
                        onFailures(new OpenSearchStatusException(response.toString(), RestStatus.REQUEST_TIMEOUT));
                    }

                    logger.debug("custom rules fetch successful");
                    SearchHits hits = response.getHits();

                    try {
                        for (SearchHit hit : hits) {
                            XContentParser xcp = XContentType.JSON.xContent().createParser(
                                    xContentRegistry,
                                    LoggingDeprecationHandler.INSTANCE, hit.getSourceAsString()
                            );

                            Rule rule = Rule.docParse(xcp, hit.getId(), hit.getVersion());
                            String id = hit.getId();

                            queries.add(Pair.of(id, rule));
                        }

                        resolveRuleFieldNamesAndUpsertMonitorFromQueries(queries, detector, logIndex, listener);
                    } catch (Exception ex) {
                        onFailures(ex);
                    }
                }

                @Override
                public void onFailure(Exception e) {
                    onFailures(e);
                }
            });
        }

        public void indexDetector() throws IOException {
            IndexRequest indexRequest;
            if (request.getMethod() == RestRequest.Method.POST) {
                indexRequest = new IndexRequest(Detector.DETECTORS_INDEX)
                        .setRefreshPolicy(request.getRefreshPolicy())
                        .source(request.getDetector().toXContentWithUser(XContentFactory.jsonBuilder(), new ToXContent.MapParams(Map.of("with_type", "true"))))
                        .timeout(indexTimeout);
            } else {
                indexRequest = new IndexRequest(Detector.DETECTORS_INDEX)
                        .setRefreshPolicy(request.getRefreshPolicy())
                        .source(request.getDetector().toXContentWithUser(XContentFactory.jsonBuilder(), new ToXContent.MapParams(Map.of("with_type", "true"))))
                        .id(request.getDetectorId())
                        .timeout(indexTimeout);
            }

            log.debug("indexing detector");
            client.index(indexRequest, new ActionListener<>() {
                @Override
                public void onResponse(IndexResponse response) {
                    log.debug("detector indexed success.");
                    Detector responseDetector = request.getDetector();
                    responseDetector.setId(response.getId());
                    onOperation(response, responseDetector);
                }

                @Override
                public void onFailure(Exception e) {
                    onFailures(e);
                }
            });
        }

        private void onOperation(IndexResponse response, Detector detector) {
            this.response.set(response);
            if (counter.compareAndSet(false, true)) {
                finishHim(detector, null);
            }
        }

        private void onFailures(Exception t) {
            if (counter.compareAndSet(false, true)) {
                finishHim(null, t);
            }
        }

        private void finishHim(Detector detector, Exception t) {
            threadPool.executor(ThreadPool.Names.GENERIC).execute(ActionRunnable.supply(listener, () -> {
                if (t != null) {
                    if (t instanceof OpenSearchStatusException) {
                        throw t;
                    }
                    throw SecurityAnalyticsException.wrap(t);
                } else {
                    return new IndexDetectorResponse(detector.getId(), detector.getVersion(), request.getMethod() == RestRequest.Method.POST? RestStatus.CREATED: RestStatus.OK, detector);
                }
            }));
        }

        private List<String> getMonitorIds(List<IndexMonitorResponse> monitorResponses) {
            return monitorResponses.stream().map(IndexMonitorResponse::getId).collect(
                Collectors.toList());
        }

        /**
         * Creates a map of monitor ids. In the case of bucket level monitors pairs are: RuleId - MonitorId
         * In the case of doc level monitor pair is DOC_LEVEL_MONITOR(value) - MonitorId
         * @param monitorResponses index monitor responses
         * @return map of monitor ids
         */
        private Map<String, String> mapMonitorIds(List<IndexMonitorResponse> monitorResponses) {
            return monitorResponses.stream().collect(
                    Collectors.toMap(
                        // In the case of bucket level monitors rule id is trigger id
                        it -> {
                            if (MonitorType.BUCKET_LEVEL_MONITOR == it.getMonitor().getMonitorType()) {
                                return it.getMonitor().getTriggers().get(0).getId();
                            } else {
                                return Detector.DOC_LEVEL_MONITOR;
                            }
                        },
                        IndexMonitorResponse::getId
                    )
                );
        }
    }

    private void setFilterByEnabled(boolean filterByEnabled) {
        this.filterByEnabled = filterByEnabled;
    }

}