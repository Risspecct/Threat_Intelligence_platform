package users.rishik.threatPlatform.attack.analysis.similarity;

import users.rishik.threatPlatform.similarity.model.SimilarityResult;

import java.util.List;

public record CandidateSimilarityReport(

        long sessionsAnalyzed,

        long candidatePairsCompared,

        long exactCommandMatches,
        long exactEventMatches,
        long exactFileHashMatches,
        long exactHasshMatches,
        long exactClientVersionMatches,
        long exactDownloadUrlMatches,
        long exactDestinationIpMatches,
        long exactDestinationPortMatches,

        long multipleCoreBehavioralMatches,

        long minimumTemporalDistanceSeconds,
        long maximumTemporalDistanceSeconds,

        List<SimilarityResult> similarities
) {
}