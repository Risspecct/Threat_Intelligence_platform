package users.rishik.threatPlatform.attack.analysis.feature;

import users.rishik.threatPlatform.attack.analysis.similarity.SimilarityStatistics;

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