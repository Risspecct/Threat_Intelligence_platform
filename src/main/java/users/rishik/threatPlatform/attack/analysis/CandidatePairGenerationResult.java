package users.rishik.threatPlatform.attack.analysis;

import java.util.EnumSet;
import java.util.Map;

public record CandidatePairGenerationResult(
        Map<CandidatePairGenerator.SessionPair,
                        EnumSet<CandidatePairGenerator.Signal>> pairSignals,
        long totalPairsBeforeDeduplication
) {
}