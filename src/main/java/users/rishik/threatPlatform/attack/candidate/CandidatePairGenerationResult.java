package users.rishik.threatPlatform.attack.candidate;

import java.util.EnumSet;
import java.util.Map;

public record CandidatePairGenerationResult(
        Map<CandidatePair, EnumSet<CandidateSignal>> pairSignals,
        long totalPairsBeforeDeduplication
) {
}