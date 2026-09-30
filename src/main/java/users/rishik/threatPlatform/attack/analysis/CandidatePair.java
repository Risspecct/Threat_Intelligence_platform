package users.rishik.threatPlatform.attack.analysis;

import java.util.Set;

public record CandidatePair(
        String sessionIdA,
        String sessionIdB,
        Set<CandidateSignal> signals
) {}