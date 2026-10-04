package users.rishik.threatPlatform.attack.mapper;

import org.junit.jupiter.api.Test;
import users.rishik.threatPlatform.attack.dto.CrossSourceEvidence;
import users.rishik.threatPlatform.attack.dto.SourceType;
import users.rishik.threatPlatform.attack.dto.ThreatObservation;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CrossSourceEvidenceMapperTest {

    @Test
    void shouldExtractCommonEvidence() {

        ThreatObservation observation = new ThreatObservation();

        observation.setSourceType(SourceType.SENTRY_PEER);
        observation.setSourceIp("10.0.0.5");
        observation.setTimestamp(
                Instant.parse("2025-06-27T10:15:30Z")
        );
        observation.setDestinationIp("10.0.0.10");
        observation.setDestinationPort(5060);
        observation.setProtocol("UDP");

        CrossSourceEvidenceMapper mapper =
                new CrossSourceEvidenceMapper();

        CrossSourceEvidence evidence = mapper.map(observation);

        assertEquals("10.0.0.5", evidence.sourceIp());
        assertEquals(
                Instant.parse("2025-06-27T10:15:30Z"),
                evidence.timestamp()
        );
        assertEquals("10.0.0.10", evidence.destinationIp());
        assertEquals(5060, evidence.destinationPort());
        assertEquals("UDP", evidence.protocol());
    }
}
