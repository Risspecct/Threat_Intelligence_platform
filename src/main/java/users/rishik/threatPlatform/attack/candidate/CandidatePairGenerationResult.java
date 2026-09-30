package users.rishik.threatPlatform.attack.candidate;

import java.util.EnumSet;
import java.util.Map;

public record CandidatePairGenerationResult(
        Map<CandidatePairGenerator.SessionPair,
                        EnumSet<CandidatePairGenerator.Signal>> pairSignals,
        long totalPairsBeforeDeduplication
) {
}