package users.rishik.threatPlatform.correlation;

import org.junit.jupiter.api.Test;
import users.rishik.threatPlatform.attack.analysis.correlation.CorrelationAssessment;
import users.rishik.threatPlatform.attack.analysis.correlation.CorrelationAssessor;
import users.rishik.threatPlatform.attack.dto.SourceType;
import users.rishik.threatPlatform.attack.dto.ThreatObservation;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertTrue;

class CorrelationAssessorTest {

    private final CorrelationAssessor assessor =
            new CorrelationAssessor();

    @Test
    void shouldAssessSharedEvidenceAndTemporalInformation() {

        ThreatObservation first = new ThreatObservation();

        first.setSourceType(SourceType.COWRIE);
        first.setSourceIp("10.0.0.5");
        first.setCommand("wget http://example.com/a");
        first.setTimestamp(
                Instant.parse("2025-06-27T10:00:00Z")
        );

        ThreatObservation second = new ThreatObservation();

        second.setSourceType(SourceType.DIONAEA);
        second.setSourceIp("10.0.0.5");
        second.setTimestamp(
                Instant.parse("2025-06-27T10:05:00Z")
        );

        CorrelationAssessment result =
                assessor.assess(first, second);

        assertTrue(result.hasSharedEvidence());
        assertTrue(result.hasTemporalInformation());
    }
}