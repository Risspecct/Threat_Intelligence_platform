package users.rishik.threatPlatform.attack.analysis.correlation;

import java.util.List;

public record CorrelationEvidenceResult(
        List<MatchedCorrelationEvidence> sharedEvidence,
        TemporalCorrelation temporalCorrelation
) {
}