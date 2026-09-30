package users.rishik.threatPlatform.attack.analysis;

import users.rishik.threatPlatform.attack.dto.SessionBehavior;
import users.rishik.threatPlatform.attack.service.RawCowrieEventReader;
import users.rishik.threatPlatform.attack.service.SessionBehaviorExtractor;
import users.rishik.threatPlatform.attack.service.SessionEventProcessor;
import users.rishik.threatPlatform.similarity.model.SimilarityResult;
import users.rishik.threatPlatform.similarity.service.SessionSimilarityService;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;

public class CandidateSimilarityAnalyzer {

    private final RawCowrieEventReader reader;
    private final SessionBehaviorExtractor extractor;
    private final CandidateGenerationRules rules;
    private final SessionSimilarityService similarityService;

    public CandidateSimilarityAnalyzer(
            RawCowrieEventReader reader,
            SessionBehaviorExtractor extractor,
            CandidateGenerationRules rules,
            SessionSimilarityService similarityService
    ) {
        this.reader = reader;
        this.extractor = extractor;
        this.rules = rules;
        this.similarityService = similarityService;
    }

    public CandidateSimilarityReport analyze(Path file)
            throws IOException {

        List<SessionBehavior> sessions =
                new ArrayList<>();

        SessionEventProcessor processor =
                new SessionEventProcessor(extractor);

        reader.read(
                file,
                event -> processor.accept(
                        event,
                        sessions::add
                )
        );

        processor.finishRemaining(sessions::add);

        return analyzeSessions(sessions);
    }

    private CandidateSimilarityReport analyzeSessions(
            List<SessionBehavior> sessions
    ) {

        Map<SessionPair, EnumSet<Signal>> candidatePairs =
                new HashMap<>();

        addSignalPairs(
                sessions,
                SessionBehavior::fileHashes,
                Signal.FILE_HASH,
                candidatePairs
        );

        addSignalPairs(
                sessions,
                SessionBehavior::downloadUrls,
                Signal.DOWNLOAD_URL,
                candidatePairs
        );

        addSignalPairs(
                sessions,
                SessionBehavior::commandSequence,
                Signal.COMMAND,
                candidatePairs
        );

        addSignalPairs(
                sessions,
                session -> {

                    String hassh = session.hassh();

                    if (hassh == null || hassh.isBlank()) {
                        return List.of();
                    }

                    return List.of(hassh);
                },
                Signal.HASSH,
                candidatePairs
        );

        long exactCommandMatches = 0;
        long exactEventMatches = 0;
        long exactFileHashMatches = 0;
        long exactHasshMatches = 0;
        long exactClientVersionMatches = 0;
        long exactDownloadUrlMatches = 0;
        long exactDestinationIpMatches = 0;
        long exactDestinationPortMatches = 0;

        long multipleCoreBehavioralMatches = 0;

        long minimumTemporalDistanceSeconds =
                Long.MAX_VALUE;

        long maximumTemporalDistanceSeconds = 0;

        for (SessionPair pair : candidatePairs.keySet()) {

            SessionBehavior first =
                    sessions.get(pair.first());

            SessionBehavior second =
                    sessions.get(pair.second());

            SimilarityResult result =
                    similarityService.compare(
                            first,
                            second
                    );

            if (hasExactNonEmptySequence(
                    first.commandSequence(),
                    second.commandSequence(),
                    result.getCommandSimilarity()
            )) {
                exactCommandMatches++;
            }

            if (hasExactNonEmptySequence(
                    first.eventSequence(),
                    second.eventSequence(),
                    result.getEventSimilarity()
            )) {
                exactEventMatches++;
            }

            if (hasExactNonEmptySet(
                    first.fileHashes(),
                    second.fileHashes(),
                    result.getFileHashSimilarity()
            )) {
                exactFileHashMatches++;
            }

            if (hasExactString(
                    first.hassh(),
                    second.hassh(),
                    result.getHasshSimilarity()
            )) {
                exactHasshMatches++;
            }

            if (hasExactString(
                    first.clientVersion(),
                    second.clientVersion(),
                    result.getClientVersionSimilarity()
            )) {
                exactClientVersionMatches++;
            }

            if (hasExactNonEmptySet(
                    first.downloadUrls(),
                    second.downloadUrls(),
                    result.getDownloadUrlSimilarity()
            )) {
                exactDownloadUrlMatches++;
            }

            if (hasExactNonEmptySet(
                    first.destinationIps(),
                    second.destinationIps(),
                    result.getDestinationIpSimilarity()
            )) {
                exactDestinationIpMatches++;
            }

            if (hasExactNonEmptySet(
                    toStringList(first.destinationPorts()),
                    toStringList(second.destinationPorts()),
                    result.getDestinationPortSimilarity()
            )) {
                exactDestinationPortMatches++;
            }

            int coreMatches = 0;

            if (hasExactNonEmptySequence(
                    first.commandSequence(),
                    second.commandSequence(),
                    result.getCommandSimilarity()
            )) {
                coreMatches++;
            }

            if (hasExactNonEmptySequence(
                    first.eventSequence(),
                    second.eventSequence(),
                    result.getEventSimilarity()
            )) {
                coreMatches++;
            }

            if (hasExactNonEmptySet(
                    first.fileHashes(),
                    second.fileHashes(),
                    result.getFileHashSimilarity()
            )) {
                coreMatches++;
            }

            if (coreMatches >= 2) {
                multipleCoreBehavioralMatches++;
            }

            long temporalDistance =
                    result.getTemporalDistanceSeconds();

            minimumTemporalDistanceSeconds =
                    Math.min(
                            minimumTemporalDistanceSeconds,
                            temporalDistance
                    );

            maximumTemporalDistanceSeconds =
                    Math.max(
                            maximumTemporalDistanceSeconds,
                            temporalDistance
                    );
        }

        if (candidatePairs.isEmpty()) {
            minimumTemporalDistanceSeconds = 0;
        }

        return new CandidateSimilarityReport(
                sessions.size(),
                candidatePairs.size(),

                exactCommandMatches,
                exactEventMatches,
                exactFileHashMatches,
                exactHasshMatches,
                exactClientVersionMatches,
                exactDownloadUrlMatches,
                exactDestinationIpMatches,
                exactDestinationPortMatches,

                multipleCoreBehavioralMatches,

                minimumTemporalDistanceSeconds,
                maximumTemporalDistanceSeconds
        );
    }

    private boolean hasExactNonEmptySequence(
            List<String> first,
            List<String> second,
            double similarity
    ) {

        return !first.isEmpty()
                && !second.isEmpty()
                && similarity == 1.0;
    }

    private boolean hasExactNonEmptySet(
            Collection<String> first,
            Collection<String> second,
            double similarity
    ) {

        return !first.isEmpty()
                && !second.isEmpty()
                && similarity == 1.0;
    }

    private boolean hasExactString(
            String first,
            String second,
            double similarity
    ) {

        return first != null
                && !first.isBlank()
                && second != null
                && !second.isBlank()
                && similarity == 1.0;
    }

    private List<String> toStringList(
            List<Integer> values
    ) {

        return values.stream()
                .filter(Objects::nonNull)
                .map(String::valueOf)
                .toList();
    }

    private void addSignalPairs(
            List<SessionBehavior> sessions,
            Function<SessionBehavior, Collection<String>> featureExtractor,
            Signal signal,
            Map<SessionPair, EnumSet<Signal>> pairSignals
    ) {

        Map<String, Long> frequencies =
                sessions.stream()
                        .flatMap(session ->
                                featureExtractor.apply(session)
                                        .stream()
                                        .filter(Objects::nonNull)
                                        .filter(value -> !value.isBlank())
                                        .distinct()
                        )
                        .collect(Collectors.groupingBy(
                                Function.identity(),
                                Collectors.counting()
                        ));

        Map<String, Long> eligible =
                FeatureFrequencyFilter.filter(
                        frequencies,
                        rules.maxFeatureFrequency()
                );

        Map<String, List<Integer>> sessionsByValue =
                new HashMap<>();

        for (int i = 0; i < sessions.size(); i++) {

            SessionBehavior session =
                    sessions.get(i);

            int finalI = i;
            featureExtractor.apply(session)
                    .stream()
                    .filter(Objects::nonNull)
                    .filter(value -> !value.isBlank())
                    .distinct()
                    .filter(eligible::containsKey)
                    .forEach(value ->
                            sessionsByValue
                                    .computeIfAbsent(
                                            value,
                                            ignored ->
                                                    new ArrayList<>()
                                    )
                                    .add(finalI)
                    );
        }

        for (List<Integer> indexes :
                sessionsByValue.values()) {

            for (int i = 0;
                 i < indexes.size();
                 i++) {

                for (int j = i + 1;
                     j < indexes.size();
                     j++) {

                    SessionPair pair =
                            new SessionPair(
                                    indexes.get(i),
                                    indexes.get(j)
                            );

                    pairSignals
                            .computeIfAbsent(
                                    pair,
                                    ignored ->
                                            EnumSet.noneOf(
                                                    Signal.class
                                            )
                            )
                            .add(signal);
                }
            }
        }
    }

    private enum Signal {
        FILE_HASH,
        DOWNLOAD_URL,
        COMMAND,
        HASSH
    }

    private record SessionPair(
            int first,
            int second
    ) {
    }
}