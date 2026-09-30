package users.rishik.threatPlatform.attack.analysis;

import users.rishik.threatPlatform.attack.dto.SessionBehavior;
import users.rishik.threatPlatform.similarity.model.SimilarityResult;
import users.rishik.threatPlatform.similarity.service.SessionSimilarityService;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public class CandidateSimilarityDistributionAnalyzer {

    private final SessionSimilarityService similarityService;

    public CandidateSimilarityDistributionAnalyzer(SessionSimilarityService similarityService) {
        this.similarityService = similarityService;
    }

    public CandidateSimilarityDistributionReport analyze(
            List<SessionBehavior> sessions,
            CandidatePairGenerationResult candidatePairs
    ) {
        Map<String, List<SimilarityResult>> resultsByCombination = new TreeMap<>();

        for (Map.Entry<CandidatePairGenerator.SessionPair,
                EnumSet<CandidatePairGenerator.Signal>> entry : candidatePairs.pairSignals().entrySet()) {
            CandidatePairGenerator.SessionPair pair = entry.getKey();
            SimilarityResult result = similarityService.compare(
                    sessions.get(pair.first()), sessions.get(pair.second()));
            resultsByCombination.computeIfAbsent(combinationName(entry.getValue()),
                    ignored -> new ArrayList<>()).add(result);
        }

        Map<String, SimilarityFeatureDistribution> distributions = new LinkedHashMap<>();
        resultsByCombination.forEach((combination, results) ->
                distributions.put(combination, calculateFeatureDistribution(results)));

        return new CandidateSimilarityDistributionReport(candidatePairs.pairSignals().size(),
                Collections.unmodifiableMap(new LinkedHashMap<>(distributions)));
    }

    public static SimilarityFeatureDistribution calculateFeatureDistribution(List<SimilarityResult> results) {
        return new SimilarityFeatureDistribution(
                calculateStatistics(results.stream().map(result -> result.getCommandSimilarity().similarity()).toList()),
                calculateStatistics(results.stream().map(result -> result.getEventSimilarity().similarity()).toList()),
                calculateStatistics(results.stream().map(result -> result.getFileHashSimilarity().similarity()).toList()),
                calculateStatistics(results.stream().map(result -> result.getHasshSimilarity().similarity()).toList()),
                calculateStatistics(results.stream().map(result -> result.getClientVersionSimilarity().similarity()).toList()),
                calculateStatistics(results.stream().map(result -> result.getDownloadUrlSimilarity().similarity()).toList()),
                calculateStatistics(results.stream().map(result -> result.getDestinationIpSimilarity().similarity()).toList()),
                calculateStatistics(results.stream().map(result -> result.getDestinationPortSimilarity().similarity()).toList()),
                calculateStatistics(results.stream().map(result -> result.getLoginBehaviorSimilarity().similarity()).toList()),
                calculateStatistics(results.stream()
                        .map(result -> (double) result.getTemporalDistanceSeconds()).toList())
        );
    }

    /** Uses p * (n - 1), with linear interpolation between adjacent values. */
    public static SimilarityStatistics calculateStatistics(List<Double> values) {
        if (values.isEmpty()) {
            throw new IllegalArgumentException("Statistics require at least one value");
        }
        List<Double> sorted = values.stream().sorted().toList();
        return new SimilarityStatistics(sorted.size(), sorted.getFirst(), percentile(sorted, .50),
                percentile(sorted, .75), percentile(sorted, .90), percentile(sorted, .95),
                sorted.getLast());
    }

    public static String combinationName(EnumSet<CandidatePairGenerator.Signal> signals) {
        return signals.stream().map(Enum::name)
                .sorted(Comparator.comparingInt(CandidateSimilarityDistributionAnalyzer::signalOrder))
                .reduce((first, second) -> first + " + " + second).orElse("NONE");
    }

    private static double percentile(List<Double> sorted, double percentile) {
        double position = percentile * (sorted.size() - 1);
        int lowerIndex = (int) Math.floor(position);
        int upperIndex = (int) Math.ceil(position);
        return sorted.get(lowerIndex) + (position - lowerIndex)
                * (sorted.get(upperIndex) - sorted.get(lowerIndex));
    }

    private static int signalOrder(String signal) {
        return switch (CandidatePairGenerator.Signal.valueOf(signal)) {
            case COMMAND -> 0;
            case DOWNLOAD_URL -> 1;
            case FILE_HASH -> 2;
            case HASSH -> 3;
        };
    }
}
