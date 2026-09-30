package users.rishik.threatPlatform.attack.analysis.feature;

import users.rishik.threatPlatform.attack.dto.SessionBehavior;
import users.rishik.threatPlatform.attack.service.RawCowrieEventReader;
import users.rishik.threatPlatform.attack.service.SessionBehaviorExtractor;
import users.rishik.threatPlatform.attack.service.SessionEventProcessor;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.ArrayList;
import java.util.function.Function;
import java.util.stream.Collectors;

public class FeatureDistributionAnalyzer {

    private static final int TOP_N = 20;

    private final RawCowrieEventReader reader;
    private final SessionBehaviorExtractor extractor;

    public FeatureDistributionAnalyzer(
            RawCowrieEventReader reader,
            SessionBehaviorExtractor extractor
    ) {
        this.reader = reader;
        this.extractor = extractor;
    }

    public FeatureDistributionReport analyze(Path file)
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

        return buildReport(sessions);
    }

    private FeatureDistributionReport buildReport(
            List<SessionBehavior> sessions
    ) {

        long sessionsWithCommands = sessions.stream()
                .filter(session ->
                        !session.commandSequence().isEmpty())
                .count();

        long sessionsWithFileHashes = sessions.stream()
                .filter(session ->
                        !session.fileHashes().isEmpty())
                .count();

        long sessionsWithHassh = sessions.stream()
                .filter(session ->
                        session.hassh() != null
                                && !session.hassh().isBlank())
                .count();

        long sessionsWithDownloadUrls = sessions.stream()
                .filter(session ->
                        !session.downloadUrls().isEmpty())
                .count();

        long sessionsWithDestinationIps = sessions.stream()
                .filter(session ->
                        !session.destinationIps().isEmpty())
                .count();

        long sessionsWithDestinationPorts = sessions.stream()
                .filter(session ->
                        !session.destinationPorts().isEmpty())
                .count();

        return new FeatureDistributionReport(
                sessions.size(),

                sessionsWithCommands,
                sessionsWithFileHashes,
                sessionsWithHassh,
                sessionsWithDownloadUrls,
                sessionsWithDestinationIps,
                sessionsWithDestinationPorts,

                countUniqueStrings(
                        sessions,
                        SessionBehavior::fileHashes
                ),

                countUniqueValues(
                        sessions,
                        SessionBehavior::hassh
                ),

                countUniqueStrings(
                        sessions,
                        SessionBehavior::downloadUrls
                ),

                countUniqueStrings(
                        sessions,
                        SessionBehavior::destinationIps
                ),

                countUniqueIntegers(
                        sessions,
                        SessionBehavior::destinationPorts
                ),

                frequencyOfCommands(sessions),

                frequencyOf(
                        sessions,
                        SessionBehavior::fileHashes
                ),

                frequencyOfHassh(sessions),

                frequencyOf(
                        sessions,
                        SessionBehavior::downloadUrls
                ),

                frequencyOf(
                        sessions,
                        SessionBehavior::destinationIps
                ),

                frequencyOfPorts(sessions)
        );
    }

    private long countUniqueStrings(
            List<SessionBehavior> sessions,
            Function<SessionBehavior, Collection<String>> extractor
    ) {

        return sessions.stream()
                .flatMap(session ->
                        extractor.apply(session).stream())
                .filter(Objects::nonNull)
                .filter(value -> !value.isBlank())
                .collect(Collectors.toSet())
                .size();
    }

    private long countUniqueIntegers(
            List<SessionBehavior> sessions,
            Function<SessionBehavior, Collection<Integer>> extractor
    ) {

        return sessions.stream()
                .flatMap(session ->
                        extractor.apply(session).stream())
                .filter(Objects::nonNull)
                .collect(Collectors.toSet())
                .size();
    }

    private long countUniqueValues(
            List<SessionBehavior> sessions,
            Function<SessionBehavior, String> extractor
    ) {

        return sessions.stream()
                .map(extractor)
                .filter(Objects::nonNull)
                .filter(value -> !value.isBlank())
                .collect(Collectors.toSet())
                .size();
    }

    private Map<String, Long> frequencyOfCommands(
            List<SessionBehavior> sessions
    ) {

        return sessions.stream()
                .flatMap(session ->
                        session.commandSequence()
                                .stream()
                                .filter(Objects::nonNull)
                                .filter(command -> !command.isBlank())
                                .distinct()
                )
                .collect(Collectors.groupingBy(
                        Function.identity(),
                        Collectors.counting()
                ))
                .entrySet()
                .stream()
                .sorted(
                        Map.Entry.<String, Long>
                                        comparingByValue()
                                .reversed()
                )
                .limit(TOP_N)
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        Map.Entry::getValue,
                        (a, b) -> a,
                        LinkedHashMap::new
                ));
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
                ))
                .entrySet()
                .stream()
                .sorted(
                        Map.Entry.<String, Long>
                                        comparingByValue()
                                .reversed()
                )
                .limit(TOP_N)
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        Map.Entry::getValue,
                        (a, b) -> a,
                        LinkedHashMap::new
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
                ))
                .entrySet()
                .stream()
                .sorted(
                        Map.Entry.<String, Long>
                                        comparingByValue()
                                .reversed()
                )
                .limit(TOP_N)
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        Map.Entry::getValue,
                        (a, b) -> a,
                        LinkedHashMap::new
                ));
    }

    private Map<Integer, Long> frequencyOfPorts(
            List<SessionBehavior> sessions
    ) {

        return sessions.stream()
                .flatMap(session ->
                        session.destinationPorts()
                                .stream()
                                .distinct()
                )
                .collect(Collectors.groupingBy(
                        Function.identity(),
                        Collectors.counting()
                ))
                .entrySet()
                .stream()
                .sorted(
                        Map.Entry.<Integer, Long>
                                        comparingByValue()
                                .reversed()
                )
                .limit(TOP_N)
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        Map.Entry::getValue,
                        (a, b) -> a,
                        LinkedHashMap::new
                ));
    }
}