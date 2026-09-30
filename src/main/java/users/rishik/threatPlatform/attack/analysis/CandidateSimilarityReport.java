package users.rishik.threatPlatform.attack.analysis;

public record CandidateSimilarityReport(

        long sessionsAnalyzed,

        long candidatePairsCompared,

        long exactCommandMatches,
        long exactEventMatches,
        long exactFileHashMatches,
        long exactHasshMatches,
        long exactClientVersionMatches,
        long exactDownloadUrlMatches,
        long exactDestinationIpMatches,
        long exactDestinationPortMatches,

        long multipleCoreBehavioralMatches,

        long minimumTemporalDistanceSeconds,
        long maximumTemporalDistanceSeconds
) {
}