package users.rishik.threatPlatform.attack.analysis;

import users.rishik.threatPlatform.attack.dto.SessionBehavior;
import users.rishik.threatPlatform.attack.service.RawCowrieEventReader;
import users.rishik.threatPlatform.attack.service.SessionBehaviorExtractor;
import users.rishik.threatPlatform.attack.service.SessionEventProcessor;

import java.io.IOException;
import java.nio.file.Path;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

public class CandidatePairOverlapAnalyzer {

    private final RawCowrieEventReader reader;
    private final SessionBehaviorExtractor extractor;
    private final CandidateGenerationRules rules;

    public CandidatePairOverlapAnalyzer(
            RawCowrieEventReader reader,
            SessionBehaviorExtractor extractor,
            CandidateGenerationRules rules
    ) {
        this.reader = reader;
        this.extractor = extractor;
        this.rules = rules;
    }

    public CandidatePairOverlapReport analyze(Path file)
            throws IOException {

        List<SessionBehavior> sessions = new ArrayList<>();

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

    private CandidatePairOverlapReport analyzeSessions(
            List<SessionBehavior> sessions
    ) {

        Map<SessionPair, EnumSet<Signal>> pairSignals =
                new HashMap<>();

        long totalPairsBeforeDeduplication = 0;

        totalPairsBeforeDeduplication += addSignalPairs(
                sessions,
                SessionBehavior::fileHashes,
                Signal.FILE_HASH,
                pairSignals
        );

        totalPairsBeforeDeduplication += addSignalPairs(
                sessions,
                SessionBehavior::downloadUrls,
                Signal.DOWNLOAD_URL,
                pairSignals
        );

        totalPairsBeforeDeduplication += addSignalPairs(
                sessions,
                SessionBehavior::commandSequence,
                Signal.COMMAND,
                pairSignals
        );

        totalPairsBeforeDeduplication += addSignalPairs(
                sessions,
                session -> {
                    String hassh = session.hassh();

                    if (hassh == null || hassh.isBlank()) {
                        return List.of();
                    }

                    return List.of(hassh);
                },
                Signal.HASSH,
                pairSignals
        );

        Map<String, Long> combinations =
                pairSignals.values()
                        .stream()
                        .collect(Collectors.groupingBy(
                                this::combinationKey,
                                Collectors.counting()
                        ));

        long singleSignalPairs =
                countBySignalCount(pairSignals, 1);

        long twoSignalPairs =
                countBySignalCount(pairSignals, 2);

        long threeSignalPairs =
                countBySignalCount(pairSignals, 3);

        long fourSignalPairs =
                countBySignalCount(pairSignals, 4);

        return new CandidatePairOverlapReport(
                sessions.size(),
                totalPairsBeforeDeduplication,
                pairSignals.size(),
                singleSignalPairs,
                twoSignalPairs,
                threeSignalPairs,
                fourSignalPairs,
                combinations
        );
    }

    private long addSignalPairs(
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

        Set<String> eligibleValues =
                FeatureFrequencyFilter.filter(
                        frequencies,
                        rules.maxFeatureFrequency()
                ).keySet();

        Map<String, List<Integer>> sessionsByValue =
                new HashMap<>();

        for (int i = 0; i < sessions.size(); i++) {

            SessionBehavior session = sessions.get(i);

            int finalI = i;
            featureExtractor.apply(session)
                    .stream()
                    .filter(Objects::nonNull)
                    .filter(value -> !value.isBlank())
                    .distinct()
                    .filter(eligibleValues::contains)
                    .forEach(value ->
                            sessionsByValue
                                    .computeIfAbsent(
                                            value,
                                            ignored -> new ArrayList<>()
                                    )
                                    .add(finalI)
                    );
        }

        long pairCount = 0;

        for (List<Integer> sessionIndexes :
                sessionsByValue.values()) {

            for (int i = 0;
                 i < sessionIndexes.size();
                 i++) {

                for (int j = i + 1;
                     j < sessionIndexes.size();
                     j++) {

                    SessionPair pair = new SessionPair(
                            sessionIndexes.get(i),
                            sessionIndexes.get(j)
                    );

                    pairSignals
                            .computeIfAbsent(
                                    pair,
                                    ignored -> EnumSet.noneOf(Signal.class)
                            )
                            .add(signal);

                    pairCount++;
                }
            }
        }

        return pairCount;
    }

    private long countBySignalCount(
            Map<SessionPair, EnumSet<Signal>> pairSignals,
            int count
    ) {

        return pairSignals.values()
                .stream()
                .filter(signals -> signals.size() == count)
                .count();
    }

    private String combinationKey(
            EnumSet<Signal> signals
    ) {

        return signals.stream()
                .map(Enum::name)
                .sorted()
                .collect(Collectors.joining("+"));
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
    ) {}
}