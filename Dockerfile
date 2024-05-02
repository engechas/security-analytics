FROM opensearchproject/opensearch:2.11.1
RUN if [ -d /usr/share/opensearch/plugins/opensearch-alerting ]; then /usr/share/opensearch/bin/opensearch-plugin remove opensearch-alerting; fi
RUN if [ -d /usr/share/opensearch/plugins/opensearch-security-analytics ]; then /usr/share/opensearch/bin/opensearch-plugin remove opensearch-security-analytics; fi
ADD build/distributions/opensearch-alerting-2.11.1.0-SNAPSHOT.zip /tmp/
ADD build/distributions/opensearch-security-analytics-2.11.1.0-SNAPSHOT.zip /tmp/
RUN /usr/share/opensearch/bin/opensearch-plugin install --batch file:/tmp/opensearch-alerting-2.11.1.0-SNAPSHOT.zip
RUN /usr/share/opensearch/bin/opensearch-plugin install --batch file:/tmp/opensearch-security-analytics-2.11.1.0-SNAPSHOT.zip
