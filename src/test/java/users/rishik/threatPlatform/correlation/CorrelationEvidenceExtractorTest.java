package users.rishik.threatPlatform.correlation;

import org.junit.jupiter.api.Test;
import users.rishik.threatPlatform.attack.analysis.correlation.CorrelationEvidence;
import users.rishik.threatPlatform.attack.analysis.correlation.CorrelationEvidenceExtractor;
import users.rishik.threatPlatform.attack.analysis.correlation.CorrelationEvidenceType;
import users.rishik.threatPlatform.attack.dto.SourceType;
import users.rishik.threatPlatform.attack.dto.ThreatObservation;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CorrelationEvidenceExtractorTest {

    private final CorrelationEvidenceExtractor extractor =
            new CorrelationEvidenceExtractor();

    @Test
    void shouldExtractCowrieEvidence() {

        ThreatObservation observation = new ThreatObservation();

        observation.setSourceType(SourceType.COWRIE);
        observation.setSourceIp("10.0.0.5");
        observation.setDestinationIp("10.0.0.10");
        observation.setDestinationPort(22);
        observation.setProtocol("ssh");

        observation.setCommand("wget http://example.com/a");
        observation.setFileHash("hash-123");
        observation.setClientFingerprint("hassh-123");

        List<CorrelationEvidence> evidence =
                extractor.extract(observation);

        assertEquals(7, evidence.size());

        assertEquals(
                "10.0.0.5",
                find(evidence, CorrelationEvidenceType.SOURCE_IP)
        );

        assertEquals(
                "wget http://example.com/a",
                find(evidence, CorrelationEvidenceType.COMMAND)
        );

        assertEquals(
                "hash-123",
                find(evidence, CorrelationEvidenceType.FILE_HASH)
        );

        assertEquals(
                "hassh-123",
                find(evidence, CorrelationEvidenceType.HASSH)
        );
    }

    @Test
    void shouldExtractDionaeaEvidence() {

        ThreatObservation observation = new ThreatObservation();

        observation.setSourceType(SourceType.DIONAEA);
        observation.setSourceIp("10.0.0.5");
        observation.setDestinationIp("10.0.0.10");
        observation.setDestinationPort(80);
        observation.setProtocol("tcp");
        observation.setService("httpd");

        List<CorrelationEvidence> evidence =
                extractor.extract(observation);

        assertEquals(5, evidence.size());

        assertEquals(
                "httpd",
                find(evidence, CorrelationEvidenceType.SERVICE)
        );
    }

    @Test
    void shouldExtractSentryPeerEvidence() {

        ThreatObservation observation = new ThreatObservation();

        observation.setSourceType(SourceType.SENTRY_PEER);
        observation.setSourceIp("10.0.0.5");
        observation.setDestinationIp("10.0.0.10");
        observation.setDestinationPort(5060);
        observation.setProtocol("UDP");
        observation.setSipUserAgent("Example-SIP-Client");
        observation.setSipMethod("INVITE");

        List<CorrelationEvidence> evidence =
                extractor.extract(observation);

        assertEquals(6, evidence.size());

        assertEquals(
                "Example-SIP-Client",
                find(evidence, CorrelationEvidenceType.SIP_USER_AGENT)
        );

        assertEquals(
                "INVITE",
                find(evidence, CorrelationEvidenceType.SIP_METHOD)
        );
    }

    private String find(
            List<CorrelationEvidence> evidence,
            CorrelationEvidenceType type) {

        return evidence.stream()
                .filter(item -> item.type() == type)
                .findFirst()
                .orElseThrow()
                .value();
    }
}