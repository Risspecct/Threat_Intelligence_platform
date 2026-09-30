package users.rishik.threatPlatform.attack;

import org.junit.jupiter.api.Test;
import users.rishik.threatPlatform.attack.analysis.similarity.CandidateSimilarityDistributionAnalyzer;
import users.rishik.threatPlatform.attack.analysis.similarity.SimilarityFeatureDistribution;
import users.rishik.threatPlatform.attack.analysis.similarity.SimilarityStatistics;
import users.rishik.threatPlatform.attack.candidate.CandidateGenerationRules;
import users.rishik.threatPlatform.attack.candidate.CandidatePairGenerationResult;
import users.rishik.threatPlatform.attack.candidate.CandidatePairGenerator;
import users.rishik.threatPlatform.attack.dto.SessionBehavior;
import users.rishik.threatPlatform.similarity.calculator.ExactMatchSimilarityCalculator;
import users.rishik.threatPlatform.similarity.calculator.LoginBehaviorSimilarityCalculator;
import users.rishik.threatPlatform.similarity.calculator.SequenceSimilarityCalculator;
import users.rishik.threatPlatform.similarity.calculator.SetSimilarityCalculator;
import users.rishik.threatPlatform.similarity.model.SimilarityResult;
import users.rishik.threatPlatform.similarity.model.FeatureSimilarity;
import users.rishik.threatPlatform.similarity.service.SessionSimilarityService;
import users.rishik.threatPlatform.attack.candidate.CandidateSignal;

import java.time.LocalDateTime;
import java.util.EnumSet;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CandidateSimilarityDistributionAnalyzerTest {

    @Test
    void shouldCalculateStatisticsForOneValue() {
        SimilarityStatistics statistics = CandidateSimilarityDistributionAnalyzer
                .calculateStatistics(List.of(4.0));

        assertEquals(1, statistics.count());
        assertEquals(4.0, statistics.min());
        assertEquals(4.0, statistics.median());
        assertEquals(4.0, statistics.p95());
        assertEquals(4.0, statistics.max());
    }

    @Test
    void shouldCalculateStatisticsForTwoValues() {
        SimilarityStatistics statistics = CandidateSimilarityDistributionAnalyzer
                .calculateStatistics(List.of(10.0, 20.0));

        assertEquals(15.0, statistics.median());
        assertEquals(17.5, statistics.p75());
        assertEquals(19.0, statistics.p90(), 0.000001);
        assertEquals(19.5, statistics.p95(), 0.000001);
    }

    @Test
    void shouldCalculateStatisticsForOddNumberOfValues() {
        SimilarityStatistics statistics = CandidateSimilarityDistributionAnalyzer
                .calculateStatistics(List.of(5.0, 1.0, 3.0));

        assertEquals(1.0, statistics.min());
        assertEquals(3.0, statistics.median());
        assertEquals(4.0, statistics.p75());
        assertEquals(4.6, statistics.p90(), 0.000001);
        assertEquals(4.8, statistics.p95(), 0.000001);
        assertEquals(5.0, statistics.max());
    }

    @Test
    void shouldCalculateStatisticsForEvenNumberOfValues() {
        SimilarityStatistics statistics = CandidateSimilarityDistributionAnalyzer
                .calculateStatistics(List.of(30.0, 0.0, 20.0, 10.0));

        assertEquals(15.0, statistics.median());
        assertEquals(22.5, statistics.p75());
        assertEquals(27.0, statistics.p90(), 0.000001);
        assertEquals(28.5, statistics.p95(), 0.000001);
    }

    @Test
    void shouldAggregateEverySimilarityDimension() {
        List<SimilarityResult> results = List.of(
                result(0.0, 0), result(0.1, 10), result(0.2, 20), result(0.3, 30));

        SimilarityFeatureDistribution distribution =
                CandidateSimilarityDistributionAnalyzer.calculateFeatureDistribution(results);

        assertEquals(4, distribution.command().count());
        assertEquals(0.0, distribution.command().min());
        assertEquals(0.15, distribution.command().median(), 0.000001);
        assertEquals(0.225, distribution.command().p75(), 0.000001);
        assertEquals(0.27, distribution.command().p90(), 0.000001);
        assertEquals(0.285, distribution.command().p95(), 0.000001);
        assertEquals(0.3, distribution.command().max());
        assertEquals(15.0, distribution.temporalDistanceSeconds().median());
    }

    @Test
    void shouldKeepExactCandidateSignalCombinationsSeparate() {
        assertEquals("COMMAND + FILE_HASH + HASSH",
                CandidateSimilarityDistributionAnalyzer.combinationName(
                        EnumSet.of(CandidateSignal.COMMAND,
                                CandidateSignal.FILE_HASH,
                                CandidateSignal.HASSH)));
        assertEquals("COMMAND + FILE_HASH",
                CandidateSimilarityDistributionAnalyzer.combinationName(
                        EnumSet.of(CandidateSignal.COMMAND,
                                CandidateSignal.FILE_HASH)));
    }

    @Test
    void shouldAnalyzeControlledCandidatePairsByExactCombination() {
        List<SessionBehavior> sessions = List.of(
                session("one", List.of("shared"), List.of("hash"), "hassh", 0),
                session("two", List.of("shared"), List.of("hash"), "hassh", 10),
                session("three", List.of("shared"), List.of("other"), "other", 20));
        CandidatePairGenerationResult pairs = new CandidatePairGenerator(
                new CandidateGenerationRules(10)).generate(sessions);

        var report = new CandidateSimilarityDistributionAnalyzer(similarityService())
                .analyze(sessions, pairs);

        assertEquals(3, report.candidatePairs());
        assertEquals(1, report.distributions().get("COMMAND + FILE_HASH + HASSH")
                .command().count());
        assertEquals(2, report.distributions().get("COMMAND").command().count());
        assertEquals(1.0, report.distributions().get("COMMAND + FILE_HASH + HASSH")
                .command().median());
    }

    private SimilarityResult result(double value, long temporalDistance) {
        FeatureSimilarity similarity = new FeatureSimilarity(value, true);
        return new SimilarityResult(similarity, similarity, similarity, similarity, similarity,
                similarity, similarity, similarity, similarity, temporalDistance, List.of());
    }

    private SessionSimilarityService similarityService() {
        return new SessionSimilarityService(new SequenceSimilarityCalculator(),
                new SetSimilarityCalculator(), new ExactMatchSimilarityCalculator(),
                new LoginBehaviorSimilarityCalculator());
    }

    private SessionBehavior session(String id, List<String> commands, List<String> hashes,
                                    String hassh, int seconds) {
        LocalDateTime firstSeen = LocalDateTime.of(2025, 1, 1, 0, 0).plusSeconds(seconds);
        return new SessionBehavior(id, "source", "honeypot", "sensor", 1, firstSeen,
                firstSeen, List.of("event"), commands, true, false, hassh, "client", hashes,
                List.of(), List.of(), List.of());
    }
}
