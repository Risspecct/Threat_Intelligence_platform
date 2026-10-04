package users.rishik.threatPlatform.correlation;

import org.junit.jupiter.api.Test;
import users.rishik.threatPlatform.attack.analysis.correlation.*;
import users.rishik.threatPlatform.attack.dto.SourceType;
import users.rishik.threatPlatform.attack.dto.ThreatObservation;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CorrelationEvidenceAnalyzerTest {

    private final CorrelationEvidenceAnalyzer analyzer =
            new CorrelationEvidenceAnalyzer();

    @Test
    void shouldIdentifySharedEvidenceAndTemporalDistance() {

        ThreatObservation first = new ThreatObservation();

        first.setSourceType(SourceType.COWRIE);
        first.setSourceIp("10.0.0.5");
        first.setDestinationIp("10.0.0.10");
        first.setDestinationPort(22);
        first.setProtocol("ssh");
        first.setCommand("wget http://example.com/a");
        first.setFileHash("hash-123");
        first.setTimestamp(
                Instant.parse("2025-06-27T10:00:00Z")
        );

        ThreatObservation second = new ThreatObservation();

        second.setSourceType(SourceType.COWRIE);
        second.setSourceIp("10.0.0.5");
        second.setDestinationIp("10.0.0.20");
        second.setDestinationPort(22);
        second.setProtocol("ssh");
        second.setCommand("wget http://example.com/a");
        second.setFileHash("hash-123");
        second.setTimestamp(
                Instant.parse("2025-06-27T10:30:00Z")
        );

        CorrelationEvidenceResult result =
                analyzer.analyze(first, second);

        List<MatchedCorrelationEvidence> shared =
                result.sharedEvidence();

        assertEquals(5, shared.size());

        assertEquals(
                "10.0.0.5",
                find(shared, CorrelationEvidenceType.SOURCE_IP)
        );

        assertEquals(
                "22",
                find(shared, CorrelationEvidenceType.DESTINATION_PORT)
        );

        assertEquals(
                "ssh",
                find(shared, CorrelationEvidenceType.PROTOCOL)
        );

        assertEquals(
                "wget http://example.com/a",
                find(shared, CorrelationEvidenceType.COMMAND)
        );

        assertEquals(
                Duration.ofMinutes(30),
                result.temporalCorrelation().distance()
        );
    }

    private String find(
            List<MatchedCorrelationEvidence> evidence,
            CorrelationEvidenceType type) {

        return evidence.stream()
                .filter(item -> item.type() == type)
                .findFirst()
                .orElseThrow()
                .firstValue();
    }

    @Test
    void shouldPreserveCommandSimilarity() {

        ThreatObservation first = new ThreatObservation();

        first.setSourceType(SourceType.COWRIE);
        first.setCommand("wget http://example.com/a");

        ThreatObservation second = new ThreatObservation();

        second.setSourceType(SourceType.COWRIE);
        second.setCommand("wget http://example.com/b");

        CorrelationEvidenceResult result =
                analyzer.analyze(first, second);

        MatchedCorrelationEvidence command =
                result.sharedEvidence()
                        .stream()
                        .filter(item ->
                                item.type() == CorrelationEvidenceType.COMMAND)
                        .findFirst()
                        .orElseThrow();

        assertEquals(
                0.96,
                command.similarity(),
                0.001
        );

        assertEquals(
                "wget http://example.com/a",
                command.firstValue()
        );

        assertEquals(
                "wget http://example.com/b",
                command.secondValue()
        );
    }

    @Test
    void shouldCalculateAverageEvidenceStrength() {

        ThreatObservation first = new ThreatObservation();

        first.setSourceType(SourceType.COWRIE);
        first.setSourceIp("10.0.0.5");
        first.setCommand("wget http://example.com/a");
        first.setFileHash("hash-123");

        ThreatObservation second = new ThreatObservation();

        second.setSourceType(SourceType.COWRIE);
        second.setSourceIp("10.0.0.5");
        second.setCommand("wget http://example.com/b");
        second.setFileHash("hash-123");

        CorrelationEvidenceResult result =
                analyzer.analyze(first, second);

        double strength =
                analyzer.calculateEvidenceStrength(result);

        // SOURCE_IP = 1.0
        // COMMAND = 0.96
        // FILE_HASH = 1.0
        // Average = 0.9866...
        assertEquals(
                0.9866,
                strength,
                0.001
        );
    }

    @Test
    void shouldClassifyEvidenceTypes() {

        assertTrue(
                CorrelationEvidenceType.COMMAND
                        .isStrongBehavioralEvidence()
        );

        assertTrue(
                CorrelationEvidenceType.FILE_HASH
                        .isStrongBehavioralEvidence()
        );

        assertTrue(
                CorrelationEvidenceType.SOURCE_IP
                        .isContextualEvidence()
        );

        assertTrue(
                CorrelationEvidenceType.DESTINATION_PORT
                        .isContextualEvidence()
        );
    }

    @Test
    void shouldCountEvidenceCategories() {

        ThreatObservation first = new ThreatObservation();

        first.setSourceType(SourceType.COWRIE);
        first.setSourceIp("10.0.0.5");
        first.setCommand("wget http://example.com/a");
        first.setFileHash("hash-123");

        ThreatObservation second = new ThreatObservation();

        second.setSourceType(SourceType.COWRIE);
        second.setSourceIp("10.0.0.5");
        second.setCommand("wget http://example.com/b");
        second.setFileHash("hash-123");

        CorrelationEvidenceResult result =
                analyzer.analyze(first, second);

        assertEquals(
                2,
                analyzer.countStrongBehavioralEvidence(result)
        );

        assertEquals(
                1,
                analyzer.countContextualEvidence(result)
        );
    }
}