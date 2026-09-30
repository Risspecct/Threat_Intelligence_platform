package users.rishik.threatPlatform.similarity.model;

/**
 * A feature's calculated similarity and whether both sessions supplied data
 * that makes the comparison meaningful as behavioral evidence.
 */
public record FeatureSimilarity(double similarity, boolean comparable) {

    public FeatureSimilarity {
        if (Double.isNaN(similarity) || similarity < 0.0 || similarity > 1.0) {
            throw new IllegalArgumentException(
                    "Similarity must be between 0.0 and 1.0"
            );
        }
    }
}
