package users.rishik.threatPlatform.correlation;

import org.junit.jupiter.api.Test;
import users.rishik.threatPlatform.attack.analysis.correlation.CorrelationEvidenceResult;
import users.rishik.threatPlatform.attack.analysis.correlation.CorrelationEvidenceType;
import users.rishik.threatPlatform.attack.analysis.correlation.CorrelationService;
import users.rishik.threatPlatform.attack.dto.SourceType;
import users.rishik.threatPlatform.attack.dto.ThreatObservation;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CorrelationServiceTest {

    private final CorrelationService service =
            new CorrelationService();

    @Test
    void shouldCorrelateTwoObservations() {

        ThreatObservation first = new ThreatObservation();

        first.setSourceType(SourceType.COWRIE);
        first.setSourceIp("10.0.0.5");
        first.setCommand("wget http://example.com/a");
        first.setFileHash("hash-123");
        first.setTimestamp(
                Instant.parse("2025-06-27T10:00:00Z")
        );

        ThreatObservation second = new ThreatObservation();

        second.setSourceType(SourceType.DIONAEA);
        second.setSourceIp("10.0.0.5");
        second.setTimestamp(
                Instant.parse("2025-06-27T10:05:00Z")
        );

        CorrelationEvidenceResult result =
                service.correlate(first, second);

        assertEquals(
                1,
                result.sharedEvidence()
                        .stream()
                        .filter(evidence ->
                                evidence.type()
                                        == CorrelationEvidenceType.SOURCE_IP)
                        .count()
        );

        assertEquals(
                300,
                result.temporalCorrelation()
                        .distance()
                        .getSeconds()
        );
    }

    @Test
    void shouldCorrelateCowrieAndDionaeaObservations() {

        ThreatObservation cowrie = new ThreatObservation();

        cowrie.setSourceType(SourceType.COWRIE);
        cowrie.setSourceIp("185.10.10.5");
        cowrie.setDestinationIp("10.0.0.10");
        cowrie.setDestinationPort(22);
        cowrie.setProtocol("ssh");
        cowrie.setCommand("wget http://example.com/a");
        cowrie.setTimestamp(
                Instant.parse("2025-06-27T10:00:00Z")
        );

        ThreatObservation dionaea = new ThreatObservation();

        dionaea.setSourceType(SourceType.DIONAEA);
        dionaea.setSourceIp("185.10.10.5");
        dionaea.setDestinationIp("10.0.0.20");
        dionaea.setDestinationPort(22);
        dionaea.setProtocol("tcp");
        dionaea.setTimestamp(
                Instant.parse("2025-06-27T10:05:00Z")
        );

        CorrelationEvidenceResult result =
                service.correlate(cowrie, dionaea);

        assertEquals(
                2,
                result.sharedEvidence().size()
        );

        assertEquals(
                300,
                result.temporalCorrelation()
                        .distance()
                        .getSeconds()
        );
    }

    @Test
    void shouldCorrelateCowrieAndSentryPeerObservations() {

        ThreatObservation cowrie = new ThreatObservation();

        cowrie.setSourceType(SourceType.COWRIE);
        cowrie.setSourceIp("185.10.10.5");
        cowrie.setDestinationIp("10.0.0.10");
        cowrie.setDestinationPort(22);
        cowrie.setProtocol("ssh");
        cowrie.setTimestamp(
                Instant.parse("2025-06-27T10:00:00Z")
        );

        ThreatObservation sentryPeer = new ThreatObservation();

        sentryPeer.setSourceType(SourceType.SENTRY_PEER);
        sentryPeer.setSourceIp("185.10.10.5");
        sentryPeer.setDestinationIp("10.0.0.30");
        sentryPeer.setDestinationPort(5060);
        sentryPeer.setProtocol("udp");
        sentryPeer.setSipMethod("INVITE");
        sentryPeer.setSipUserAgent("Example-UA");
        sentryPeer.setTimestamp(
                Instant.parse("2025-06-27T10:10:00Z")
        );

        CorrelationEvidenceResult result =
                service.correlate(cowrie, sentryPeer);

        assertEquals(
                1,
                result.sharedEvidence()
                        .stream()
                        .filter(evidence ->
                                evidence.type()
                                        == CorrelationEvidenceType.SOURCE_IP)
                        .count()
        );

        assertEquals(
                600,
                result.temporalCorrelation()
                        .distance()
                        .getSeconds()
        );
    }

    @Test
    void shouldCorrelateDionaeaAndSentryPeerObservations() {

        ThreatObservation dionaea = new ThreatObservation();

        dionaea.setSourceType(SourceType.DIONAEA);
        dionaea.setSourceIp("185.10.10.5");
        dionaea.setDestinationIp("10.0.0.20");
        dionaea.setDestinationPort(80);
        dionaea.setProtocol("tcp");
        dionaea.setTimestamp(
                Instant.parse("2025-06-27T10:00:00Z")
        );

        ThreatObservation sentryPeer = new ThreatObservation();

        sentryPeer.setSourceType(SourceType.SENTRY_PEER);
        sentryPeer.setSourceIp("185.10.10.5");
        sentryPeer.setDestinationIp("10.0.0.30");
        sentryPeer.setDestinationPort(5060);
        sentryPeer.setProtocol("udp");
        sentryPeer.setSipMethod("INVITE");
        sentryPeer.setSipUserAgent("Example-UA");
        sentryPeer.setTimestamp(
                Instant.parse("2025-06-27T10:15:00Z")
        );

        CorrelationEvidenceResult result =
                service.correlate(dionaea, sentryPeer);

        assertEquals(
                1,
                result.sharedEvidence()
                        .stream()
                        .filter(evidence ->
                                evidence.type()
                                        == CorrelationEvidenceType.SOURCE_IP)
                        .count()
        );

        assertEquals(
                900,
                result.temporalCorrelation()
                        .distance()
                        .getSeconds()
        );
    }
}