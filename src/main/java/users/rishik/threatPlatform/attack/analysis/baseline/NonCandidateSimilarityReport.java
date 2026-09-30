package users.rishik.threatPlatform.attack.analysis.baseline;

import users.rishik.threatPlatform.similarity.model.SimilarityResult;

import java.util.List;

public record NonCandidateSimilarityReport(
        int sessionCount,
        int sampleSize,
        long seed,
        List<SimilarityResult> similarities
) {
}