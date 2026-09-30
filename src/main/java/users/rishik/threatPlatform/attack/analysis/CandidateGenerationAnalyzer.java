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

public class CandidateGenerationAnalyzer {

    private final RawCowrieEventReader reader;
    private final SessionBehaviorExtractor extractor;
    private final CandidateGenerationRules rules;

    public CandidateGenerationAnalyzer(
            RawCowrieEventReader reader,
            SessionBehaviorExtractor extractor,
            CandidateGenerationRules rules
    ) {
        this.reader = reader;
        this.extractor = extractor;
        this.rules = rules;
    }

    public CandidateGenerationReport analyze(Path file)
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

    private CandidateGenerationReport analyzeSessions(
            List<SessionBehavior> sessions
    ) {

        Map<String, Long> fileHashFrequencies =
                frequencyOf(
                        sessions,
                        SessionBehavior::fileHashes
                );

        Map<String, Long> urlFrequencies =
                frequencyOf(
                        sessions,
                        SessionBehavior::downloadUrls
                );

        Map<String, Long> commandFrequencies =
                frequencyOf(
                        sessions,
                        SessionBehavior::commandSequence
                );

        Map<String, Long> hasshFrequencies =
                frequencyOfHassh(sessions);

        Map<String, Long> eligibleFileHashes =
                FeatureFrequencyFilter.filter(
                        fileHashFrequencies,
                        rules.maxFeatureFrequency()
                );

        Map<String, Long> eligibleUrls =
                FeatureFrequencyFilter.filter(
                        urlFrequencies,
                        rules.maxFeatureFrequency()
                );

        Map<String, Long> eligibleCommands =
                FeatureFrequencyFilter.filter(
                        commandFrequencies,
                        rules.maxFeatureFrequency()
                );

        Map<String, Long> eligibleHassh =
                FeatureFrequencyFilter.filter(
                        hasshFrequencies,
                        rules.maxFeatureFrequency()
                );

        long fileHashPairs =
                countPairs(eligibleFileHashes);

        long urlPairs =
                countPairs(eligibleUrls);

        long commandPairs =
                countPairs(eligibleCommands);

        long hasshPairs =
                countPairs(eligibleHassh);

        return new CandidateGenerationReport(
                sessions.size(),

                eligibleFileHashes.size(),
                eligibleUrls.size(),
                eligibleCommands.size(),
                eligibleHassh.size(),

                fileHashPairs,
                urlPairs,
                commandPairs,
                hasshPairs
        );
    }

    private long countPairs(
            Map<String, Long> frequencies
    ) {

        long pairs = 0;

        for (long frequency : frequencies.values()) {
            pairs += frequency * (frequency - 1) / 2;
        }

        return pairs;
    }

    private Map<String, Long> frequencyOf(
            List<SessionBehavior> sessions,
            Function<SessionBehavior, Collection<String>> extractor
    ) {

        return sessions.stream()
                .flatMap(session ->
                        extractor.apply(session)
                                .stream()
                                .filter(Objects::nonNull)
                                .filter(value -> !value.isBlank())
                                .distinct()
                )
                .collect(Collectors.groupingBy(
                        Function.identity(),
                        Collectors.counting()
                ));
    }

    private Map<String, Long> frequencyOfHassh(
            List<SessionBehavior> sessions
    ) {

        return sessions.stream()
                .map(SessionBehavior::hassh)
                .filter(Objects::nonNull)
                .filter(value -> !value.isBlank())
                .collect(Collectors.groupingBy(
                        Function.identity(),
                        Collectors.counting()
                ));
    }
}