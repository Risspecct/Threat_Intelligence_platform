package users.rishik.threatPlatform.attack.analysis;

public record CandidateGenerationRules(
        int maxFeatureFrequency
) {

    public static CandidateGenerationRules defaults() {
        return new CandidateGenerationRules(100);
    }

    public CandidateGenerationRules {
        if (maxFeatureFrequency < 2) {
            throw new IllegalArgumentException(
                    "Maximum feature frequency must be at least 2"
            );
        }
    }
}