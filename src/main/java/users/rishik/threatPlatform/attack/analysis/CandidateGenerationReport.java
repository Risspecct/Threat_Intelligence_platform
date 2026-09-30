package users.rishik.threatPlatform.attack.analysis;

public record CandidateGenerationReport(

        long sessionsAnalyzed,

        long eligibleFileHashValues,
        long eligibleUrlValues,
        long eligibleCommandValues,
        long eligibleHasshValues,

        long fileHashCandidatePairs,
        long urlCandidatePairs,
        long commandCandidatePairs,
        long hasshCandidatePairs
) {

    public long totalCandidatePairsBeforeDeduplication() {
        return fileHashCandidatePairs
                + urlCandidatePairs
                + commandCandidatePairs
                + hasshCandidatePairs;
    }

    public long allPossiblePairs() {
        return sessionsAnalyzed
                * (sessionsAnalyzed - 1)
                / 2;
    }

    public double candidateReductionPercentage() {

        long allPairs = allPossiblePairs();

        if (allPairs == 0) {
            return 0.0;
        }

        return 100.0 * (
                1.0
                        - ((double) totalCandidatePairsBeforeDeduplication()
                        / allPairs)
        );
    }
}