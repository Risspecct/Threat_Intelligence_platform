package users.rishik.threatPlatform.attack.analysis.similarity;

import java.util.Map;

public record CandidateSimilarityDistributionReport(
        long candidatePairs,
        Map<String, SimilarityFeatureDistribution> distributions
) {
}
