package users.rishik.threatPlatform.attack;

import org.junit.jupiter.api.Test;
import users.rishik.threatPlatform.attack.dto.CrossSourceEvidence;
import users.rishik.threatPlatform.attack.dto.ThreatObservation;
import users.rishik.threatPlatform.attack.mapper.CrossSourceEvidenceMapper;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CrossSourceEvidenceNormalizationTest {

    private final CrossSourceEvidenceMapper mapper =
            new CrossSourceEvidenceMapper();

    @Test
    void shouldExtractCommonEvidenceFromCowrie() {

        ThreatObservation observation = new ThreatObservation();

        observation.setSourceIp("10.0.0.5");
        observation.setTimestamp(
                Instant.parse("2025-06-27T10:15:30Z")
        );
        observation.setDestinationIp("10.0.0.10");
        observation.setDestinationPort(22);
        observation.setProtocol("ssh");

        CrossSourceEvidence evidence = mapper.map(observation);

        assertEquals("10.0.0.5", evidence.sourceIp());
        assertEquals("10.0.0.10", evidence.destinationIp());
        assertEquals(22, evidence.destinationPort());
        assertEquals("ssh", evidence.protocol());
    }

    @Test
    void shouldExtractCommonEvidenceFromDionaea() {

        ThreatObservation observation = new ThreatObservation();

        observation.setSourceIp("10.0.0.20");
        observation.setTimestamp(
                Instant.parse("2025-06-27T11:15:30Z")
        );
        observation.setDestinationIp("10.0.0.30");
        observation.setDestinationPort(80);
        observation.setProtocol("tcp");

        CrossSourceEvidence evidence = mapper.map(observation);

        assertEquals("10.0.0.20", evidence.sourceIp());
        assertEquals("10.0.0.30", evidence.destinationIp());
        assertEquals(80, evidence.destinationPort());
        assertEquals("tcp", evidence.protocol());
    }

    @Test
    void shouldExtractCommonEvidenceFromSentryPeer() {

        ThreatObservation observation = new ThreatObservation();

        observation.setSourceIp("10.0.0.40");
        observation.setTimestamp(
                Instant.parse("2025-06-27T12:15:30Z")
        );
        observation.setDestinationIp("10.0.0.50");
        observation.setDestinationPort(5060);
        observation.setProtocol("UDP");

        CrossSourceEvidence evidence = mapper.map(observation);

        assertEquals("10.0.0.40", evidence.sourceIp());
        assertEquals("10.0.0.50", evidence.destinationIp());
        assertEquals(5060, evidence.destinationPort());
        assertEquals("UDP", evidence.protocol());
    }
}