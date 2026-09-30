package users.rishik.threatPlatform.attack.analysis.similarity;

/** Distribution statistics for every dimension returned by a session comparison. */
public record SimilarityFeatureDistribution(
        SimilarityStatistics command,
        SimilarityStatistics event,
        SimilarityStatistics fileHash,
        SimilarityStatistics hassh,
        SimilarityStatistics clientVersion,
        SimilarityStatistics downloadUrl,
        SimilarityStatistics destinationIp,
        SimilarityStatistics destinationPort,
        SimilarityStatistics loginBehavior,
        SimilarityStatistics temporalDistanceSeconds
) {
}
