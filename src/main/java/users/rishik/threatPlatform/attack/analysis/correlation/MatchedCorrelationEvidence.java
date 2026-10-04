package users.rishik.threatPlatform.attack.analysis.correlation;

public record MatchedCorrelationEvidence(
        CorrelationEvidenceType type,
        String firstValue,
        String secondValue,
        double similarity
) {
}