package users.rishik.threatPlatform.attack.analysis.correlation;

public record CorrelationAssessment(
        CorrelationEvidenceResult evidence,
        boolean hasSharedEvidence,
        boolean hasTemporalInformation
) {
}