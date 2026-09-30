package users.rishik.threatPlatform.attack.analysis;

import java.util.Map;

public record FeatureDistributionReport(
        long sessionsAnalyzed,

        long sessionsWithCommands,
        long sessionsWithFileHashes,
        long sessionsWithHassh,
        long sessionsWithDownloadUrls,
        long sessionsWithDestinationIps,
        long sessionsWithDestinationPorts,

        long uniqueFileHashes,
        long uniqueHasshValues,
        long uniqueDownloadUrls,
        long uniqueDestinationIps,
        long uniqueDestinationPorts,

        Map<String, Long> topCommands,
        Map<String, Long> topFileHashes,
        Map<String, Long> topHasshValues,
        Map<String, Long> topDownloadUrls,
        Map<String, Long> topDestinationIps,
        Map<Integer, Long> topDestinationPorts
) {
}