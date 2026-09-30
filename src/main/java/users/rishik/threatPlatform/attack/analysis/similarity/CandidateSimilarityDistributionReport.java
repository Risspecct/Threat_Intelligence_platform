package users.rishik.threatPlatform.attack.analysis.similarity;

import users.rishik.threatPlatform.similarity.model.SimilarityResult;

import java.util.List;
import java.util.Map;

public record CandidateSimilarityDistributionReport(
        long candidatePairs,
        Map<String, SimilarityFeatureDistribution> distributions,
        List<SimilarityResult> similarities
) {
}
