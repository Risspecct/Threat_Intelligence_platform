package users.rishik.threatPlatform.attack.analysis.correlation;

import users.rishik.threatPlatform.attack.dto.ThreatObservation;

public class CorrelationAssessor {

    private final CorrelationEvidenceAnalyzer analyzer =
            new CorrelationEvidenceAnalyzer();

    public CorrelationAssessment assess(
            ThreatObservation first,
            ThreatObservation second) {

        CorrelationEvidenceResult evidence =
                analyzer.analyze(first, second);

        boolean hasSharedEvidence =
                !evidence.sharedEvidence().isEmpty();

        boolean hasTemporalInformation =
                evidence.temporalCorrelation() != null
                        && evidence.temporalCorrelation().distance() != null;

        return new CorrelationAssessment(
                evidence,
                hasSharedEvidence,
                hasTemporalInformation
        );
    }
}