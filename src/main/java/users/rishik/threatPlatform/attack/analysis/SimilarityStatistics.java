package users.rishik.threatPlatform.attack.analysis;

public record SimilarityStatistics(
        long count,
        double min,
        double median,
        double p75,
        double p90,
        double p95,
        double max
) {
}