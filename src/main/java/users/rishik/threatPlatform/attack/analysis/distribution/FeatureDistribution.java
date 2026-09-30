package users.rishik.threatPlatform.attack.analysis.distribution;

public record FeatureDistribution(
        long totalCount,
        long comparableCount,
        double comparableRate,
        double mean,
        double p25,
        double median,
        double p75,
        double p90,
        double p95,
        double p99,
        double min,
        double max
) {
}