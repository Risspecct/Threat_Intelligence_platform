package users.rishik.threatPlatform.attack.analysis;


import users.rishik.threatPlatform.attack.dto.SessionBehavior;
import users.rishik.threatPlatform.attack.service.RawCowrieEventReader;
import users.rishik.threatPlatform.attack.service.SessionBehaviorExtractor;
import users.rishik.threatPlatform.attack.service.SessionEventProcessor;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class CandidatePairOverlapAnalyzer {

    private final CandidatePairGenerator candidatePairGenerator;
    private final RawCowrieEventReader reader;
    private final SessionBehaviorExtractor extractor;

    public CandidatePairOverlapAnalyzer(
            CandidatePairGenerator candidatePairGenerator,
            RawCowrieEventReader reader,
            SessionBehaviorExtractor extractor
    ) {
        this.candidatePairGenerator = candidatePairGenerator;
        this.reader = reader;
        this.extractor = extractor;
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

        processor.finishRemaining(
                sessions::add
        );

        return analyzeSessions(sessions);
    }

    private CandidatePairOverlapReport analyzeSessions(
            List<SessionBehavior> sessions
    ) {

        CandidatePairGenerationResult result =
                candidatePairGenerator.generate(sessions);

        Map<CandidatePairGenerator.SessionPair,
                EnumSet<CandidatePairGenerator.Signal>> pairSignals =
                result.pairSignals();

        long totalPairsBeforeDeduplication =
                result.totalPairsBeforeDeduplication();

        Map<String, Long> combinations =
                pairSignals.values()
                        .stream()
                        .collect(Collectors.groupingBy(
                                this::combinationKey,
                                Collectors.counting()
                        ));

        long uniqueCandidatePairs =
                pairSignals.size();

        long singleSignalPairs =
                combinations.entrySet()
                        .stream()
                        .filter(entry ->
                                signalCount(entry.getKey()) == 1)
                        .mapToLong(Map.Entry::getValue)
                        .sum();

        long twoSignalPairs =
                combinations.entrySet()
                        .stream()
                        .filter(entry ->
                                signalCount(entry.getKey()) == 2)
                        .mapToLong(Map.Entry::getValue)
                        .sum();

        long threeSignalPairs =
                combinations.entrySet()
                        .stream()
                        .filter(entry ->
                                signalCount(entry.getKey()) == 3)
                        .mapToLong(Map.Entry::getValue)
                        .sum();

        long fourSignalPairs =
                combinations.entrySet()
                        .stream()
                        .filter(entry ->
                                signalCount(entry.getKey()) == 4)
                        .mapToLong(Map.Entry::getValue)
                        .sum();

        return new CandidatePairOverlapReport(
                sessions.size(),
                totalPairsBeforeDeduplication,
                uniqueCandidatePairs,
                singleSignalPairs,
                twoSignalPairs,
                threeSignalPairs,
                fourSignalPairs,
                combinations
        );
    }

    private String combinationKey(
            EnumSet<CandidatePairGenerator.Signal> signals
    ) {

        return signals.stream()
                .map(Enum::name)
                .sorted()
                .collect(Collectors.joining("+"));
    }

    private int signalCount(String combination) {

        return combination.split("\\+").length;
    }
}