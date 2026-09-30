package users.rishik.threatPlatform.attack.analysis.distribution;

import users.rishik.threatPlatform.similarity.model.FeatureSimilarity;
import users.rishik.threatPlatform.similarity.model.SimilarityResult;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

public class SimilarityDistributionAnalyzer {

    public Map<SimilarityFeature, FeatureDistribution> analyze(
            List<SimilarityResult> results
    ) {

        Map<SimilarityFeature, FeatureDistribution> distributions =
                new EnumMap<>(SimilarityFeature.class);

        distributions.put(
                SimilarityFeature.COMMAND,
                analyzeFeature(
                        results,
                        SimilarityResult::getCommandSimilarity
                )
        );

        distributions.put(
                SimilarityFeature.EVENT,
                analyzeFeature(
                        results,
                        SimilarityResult::getEventSimilarity
                )
        );

        distributions.put(
                SimilarityFeature.FILE_HASH,
                analyzeFeature(
                        results,
                        SimilarityResult::getFileHashSimilarity
                )
        );

        distributions.put(
                SimilarityFeature.HASSH,
                analyzeFeature(
                        results,
                        SimilarityResult::getHasshSimilarity
                )
        );

        distributions.put(
                SimilarityFeature.CLIENT_VERSION,
                analyzeFeature(
                        results,
                        SimilarityResult::getClientVersionSimilarity
                )
        );

        distributions.put(
                SimilarityFeature.DOWNLOAD_URL,
                analyzeFeature(
                        results,
                        SimilarityResult::getDownloadUrlSimilarity
                )
        );

        distributions.put(
                SimilarityFeature.DESTINATION_IP,
                analyzeFeature(
                        results,
                        SimilarityResult::getDestinationIpSimilarity
                )
        );

        distributions.put(
                SimilarityFeature.DESTINATION_PORT,
                analyzeFeature(
                        results,
                        SimilarityResult::getDestinationPortSimilarity
                )
        );

        distributions.put(
                SimilarityFeature.LOGIN_BEHAVIOR,
                analyzeFeature(
                        results,
                        SimilarityResult::getLoginBehaviorSimilarity
                )
        );

        distributions.put(
                SimilarityFeature.TEMPORAL_DISTANCE,
                analyzeTemporalDistance(results)
        );

        return distributions;
    }

    private FeatureDistribution analyzeFeature(
            List<SimilarityResult> results,
            Function<SimilarityResult, FeatureSimilarity> extractor
    ) {

        List<Double> values = new ArrayList<>();

        long comparableCount = 0;

        for (SimilarityResult result : results) {

            FeatureSimilarity feature =
                    extractor.apply(result);

            if (!feature.comparable()) {
                continue;
            }

            values.add(feature.similarity());
            comparableCount++;
        }

        return createDistribution(
                results.size(),
                comparableCount,
                values
        );
    }

    private FeatureDistribution analyzeTemporalDistance(
            List<SimilarityResult> results
    ) {

        List<Double> values =
                results.stream()
                        .map(result ->
                                (double) result.getTemporalDistanceSeconds()
                        )
                        .toList();

        return createDistribution(
                values.size(),
                values.size(),
                values
        );
    }

    private FeatureDistribution createDistribution(
            long totalCount,
            long comparableCount,
            List<Double> values
    ) {

        if (values.isEmpty()) {

            return new FeatureDistribution(
                    totalCount,
                    0,
                    0.0,
                    Double.NaN,
                    Double.NaN,
                    Double.NaN,
                    Double.NaN,
                    Double.NaN,
                    Double.NaN,
                    Double.NaN,
                    Double.NaN,
                    Double.NaN
            );
        }

        List<Double> sorted =
                values.stream()
                        .sorted(Comparator.naturalOrder())
                        .toList();

        double comparableRate =
                (double) comparableCount / totalCount;

        return new FeatureDistribution(
                totalCount,
                comparableCount,
                comparableRate,
                mean(sorted),
                percentile(sorted, 0.25),
                percentile(sorted, 0.50),
                percentile(sorted, 0.75),
                percentile(sorted, 0.90),
                percentile(sorted, 0.95),
                percentile(sorted, 0.99),
                sorted.getFirst(),
                sorted.getLast()
        );
    }

    private double mean(List<Double> values) {

        double sum = 0.0;

        for (double value : values) {
            sum += value;
        }

        return sum / values.size();
    }

    private double percentile(
            List<Double> sorted,
            double percentile
    ) {

        if (sorted.size() == 1) {
            return sorted.getFirst();
        }

        double position =
                percentile * (sorted.size() - 1);

        int lower =
                (int) Math.floor(position);

        int upper =
                (int) Math.ceil(position);

        if (lower == upper) {
            return sorted.get(lower);
        }

        double weight =
                position - lower;

        return sorted.get(lower)
                + weight *
                (sorted.get(upper) - sorted.get(lower));
    }
}