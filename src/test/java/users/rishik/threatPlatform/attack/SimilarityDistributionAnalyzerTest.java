package users.rishik.threatPlatform.attack;

import org.junit.jupiter.api.Test;
import users.rishik.threatPlatform.attack.analysis.distribution.FeatureDistribution;
import users.rishik.threatPlatform.attack.analysis.distribution.SimilarityDistributionAnalyzer;
import users.rishik.threatPlatform.attack.analysis.distribution.SimilarityFeature;
import users.rishik.threatPlatform.similarity.model.FeatureSimilarity;
import users.rishik.threatPlatform.similarity.model.SimilarityResult;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SimilarityDistributionAnalyzerTest {

    private final SimilarityDistributionAnalyzer analyzer =
            new SimilarityDistributionAnalyzer();

    @Test
    void shouldCalculateStatisticsForComparableValues() {

        List<SimilarityResult> results = List.of(
                result(0.0, true, 0),
                result(0.25, true, 10),
                result(0.5, true, 20),
                result(0.75, true, 30),
                result(1.0, true, 40)
        );

        Map<SimilarityFeature, FeatureDistribution> distributions =
                analyzer.analyze(results);

        FeatureDistribution command =
                distributions.get(SimilarityFeature.COMMAND);

        assertEquals(5, command.totalCount());
        assertEquals(5, command.comparableCount());
        assertEquals(1.0, command.comparableRate());

        assertEquals(0.5, command.mean(), 0.000001);
        assertEquals(0.25, command.p25(), 0.000001);
        assertEquals(0.5, command.median(), 0.000001);
        assertEquals(0.75, command.p75(), 0.000001);
        assertEquals(0.9, command.p90(), 0.000001);
        assertEquals(0.95, command.p95(), 0.000001);
        assertEquals(0.99, command.p99(), 0.000001);
        assertEquals(0.0, command.min(), 0.000001);
        assertEquals(1.0, command.max(), 0.000001);
    }

    @Test
    void shouldExcludeNonComparableValuesFromBehavioralStatistics() {

        List<SimilarityResult> results = List.of(
                result(1.0, false, 0),
                result(0.2, true, 10),
                result(0.4, true, 20)
        );

        Map<SimilarityFeature, FeatureDistribution> distributions =
                analyzer.analyze(results);

        FeatureDistribution command =
                distributions.get(SimilarityFeature.COMMAND);

        assertEquals(3, command.totalCount());
        assertEquals(2, command.comparableCount());

        assertEquals(
                2.0 / 3.0,
                command.comparableRate(),
                0.000001
        );

        assertEquals(0.3, command.mean(), 0.000001);
        assertEquals(0.3, command.median(), 0.000001);
        assertEquals(0.2, command.min(), 0.000001);
        assertEquals(0.4, command.max(), 0.000001);
    }

    @Test
    void shouldCalculateTemporalDistanceForEveryResult() {

        List<SimilarityResult> results = List.of(
                result(0.0, true, 10),
                result(0.0, true, 20),
                result(0.0, true, 30),
                result(0.0, true, 40),
                result(0.0, true, 50)
        );

        Map<SimilarityFeature, FeatureDistribution> distributions =
                analyzer.analyze(results);

        FeatureDistribution temporal =
                distributions.get(
                        SimilarityFeature.TEMPORAL_DISTANCE
                );

        assertEquals(5, temporal.totalCount());
        assertEquals(5, temporal.comparableCount());
        assertEquals(1.0, temporal.comparableRate());

        assertEquals(30.0, temporal.mean(), 0.000001);
        assertEquals(20.0, temporal.p25(), 0.000001);
        assertEquals(30.0, temporal.median(), 0.000001);
        assertEquals(40.0, temporal.p75(), 0.000001);
        assertEquals(46.0, temporal.p90(), 0.000001);
        assertEquals(48.0, temporal.p95(), 0.000001);
        assertEquals(49.6, temporal.p99(), 0.000001);
        assertEquals(10.0, temporal.min(), 0.000001);
        assertEquals(50.0, temporal.max(), 0.000001);
    }

    @Test
    void shouldReturnEmptyStatisticsWhenNoValuesAreComparable() {

        List<SimilarityResult> results = List.of(
                result(1.0, false, 10),
                result(1.0, false, 20),
                result(1.0, false, 30)
        );

        Map<SimilarityFeature, FeatureDistribution> distributions =
                analyzer.analyze(results);

        FeatureDistribution command =
                distributions.get(SimilarityFeature.COMMAND);

        assertEquals(3, command.totalCount());
        assertEquals(0, command.comparableCount());
        assertEquals(0.0, command.comparableRate());

        assertTrue(Double.isNaN(command.mean()));
        assertTrue(Double.isNaN(command.p25()));
        assertTrue(Double.isNaN(command.median()));
        assertTrue(Double.isNaN(command.p75()));
        assertTrue(Double.isNaN(command.p90()));
        assertTrue(Double.isNaN(command.p95()));
        assertTrue(Double.isNaN(command.p99()));
        assertTrue(Double.isNaN(command.min()));
        assertTrue(Double.isNaN(command.max()));
    }

    @Test
    void shouldAnalyzeAllSimilarityFeatures() {

        List<SimilarityResult> results = List.of(
                result(0.5, true, 100)
        );

        Map<SimilarityFeature, FeatureDistribution> distributions =
                analyzer.analyze(results);

        assertEquals(
                10,
                distributions.size()
        );

        for (SimilarityFeature feature :
                SimilarityFeature.values()) {

            assertTrue(
                    distributions.containsKey(feature),
                    "Missing distribution for " + feature
            );
        }
    }

    private SimilarityResult result(
            double similarity,
            boolean comparable,
            long temporalDistance
    ) {

        FeatureSimilarity feature =
                new FeatureSimilarity(
                        similarity,
                        comparable
                );

        return new SimilarityResult(
                feature, // command
                feature, // event
                feature, // file hash
                feature, // hassh
                feature, // client version
                feature, // download URL
                feature, // destination IP
                feature, // destination port
                feature, // login behavior
                temporalDistance,
                List.of()
        );
    }
}