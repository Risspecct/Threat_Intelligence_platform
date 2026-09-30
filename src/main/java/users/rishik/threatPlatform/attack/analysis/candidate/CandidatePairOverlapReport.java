package users.rishik.threatPlatform.attack.analysis.candidate;

import java.util.Map;

public record CandidatePairOverlapReport(
        long sessionsAnalyzed,

        long totalCandidatePairsBeforeDeduplication,
        long uniqueCandidatePairs,

        long singleSignalPairs,
        long twoSignalPairs,
        long threeSignalPairs,
        long fourSignalPairs,

        Map<String, Long> signalCombinationCounts
) {}