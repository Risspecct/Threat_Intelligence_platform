package users.rishik.threatPlatform.attack.analysis;

public record FeatureDistribution(
        SimilarityStatistics command,
        SimilarityStatistics event,
        SimilarityStatistics fileHash,
        SimilarityStatistics hassh,
        SimilarityStatistics clientVersion,
        SimilarityStatistics downloadUrl,
        SimilarityStatistics destinationIp,
        SimilarityStatistics destinationPort,
        SimilarityStatistics loginBehavior
) {
}