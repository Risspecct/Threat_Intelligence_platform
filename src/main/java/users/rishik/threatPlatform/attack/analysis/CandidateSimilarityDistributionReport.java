package users.rishik.threatPlatform.attack.analysis;

import java.util.Map;

public record CandidateSimilarityDistributionReport(
        long candidatePairs,
        Map<String, SimilarityFeatureDistribution> distributions
) {
}
