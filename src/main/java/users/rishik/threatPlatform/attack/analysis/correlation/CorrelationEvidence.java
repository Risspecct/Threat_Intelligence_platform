package users.rishik.threatPlatform.attack.analysis.correlation;

public record CorrelationEvidence(
        CorrelationEvidenceType type,
        String value
) {
}