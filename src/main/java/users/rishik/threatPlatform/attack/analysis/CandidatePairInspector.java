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
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class CandidatePairInspector {

    private final CandidatePairGenerator candidatePairGenerator;
    private final RawCowrieEventReader reader;
    private final SessionBehaviorExtractor extractor;
    private final SessionSimilarityService similarityService;

    public CandidatePairInspector(
            CandidatePairGenerator candidatePairGenerator,
            RawCowrieEventReader reader,
            SessionBehaviorExtractor extractor,
            SessionSimilarityService similarityService
    ) {
        this.candidatePairGenerator = candidatePairGenerator;
        this.reader = reader;
        this.extractor = extractor;
        this.similarityService = similarityService;
    }

    public void inspect(Path file) throws IOException {

        List<SessionBehavior> sessions = loadSessions(file);

        CandidatePairGenerationResult result =
                candidatePairGenerator.generate(sessions);

        Map<CandidatePairGenerator.SessionPair,
                EnumSet<CandidatePairGenerator.Signal>> pairSignals =
                result.pairSignals();

        inspectCombination(
                "HASSH",
                EnumSet.of(
                        CandidatePairGenerator.Signal.HASSH
                ),
                pairSignals,
                sessions
        );

        inspectCombination(
                "COMMAND + FILE_HASH",
                EnumSet.of(
                        CandidatePairGenerator.Signal.COMMAND,
                        CandidatePairGenerator.Signal.FILE_HASH
                ),
                pairSignals,
                sessions
        );

        inspectCombination(
                "COMMAND + FILE_HASH + HASSH",
                EnumSet.of(
                        CandidatePairGenerator.Signal.COMMAND,
                        CandidatePairGenerator.Signal.FILE_HASH,
                        CandidatePairGenerator.Signal.HASSH
                ),
                pairSignals,
                sessions
        );

        inspectCombination(
                "COMMAND + DOWNLOAD_URL + FILE_HASH",
                EnumSet.of(
                        CandidatePairGenerator.Signal.COMMAND,
                        CandidatePairGenerator.Signal.DOWNLOAD_URL,
                        CandidatePairGenerator.Signal.FILE_HASH
                ),
                pairSignals,
                sessions
        );
    }

    private List<SessionBehavior> loadSessions(Path file)
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

        processor.finishRemaining(
                sessions::add
        );

        return sessions;
    }

    private void inspectCombination(
            String name,
            EnumSet<CandidatePairGenerator.Signal> requiredSignals,
            Map<CandidatePairGenerator.SessionPair,
                    EnumSet<CandidatePairGenerator.Signal>> pairSignals,
            List<SessionBehavior> sessions
    ) {

        Optional<
                Map.Entry<
                        CandidatePairGenerator.SessionPair,
                        EnumSet<CandidatePairGenerator.Signal>
                        >
                > match =
                pairSignals.entrySet()
                        .stream()
                        .filter(entry ->
                                entry.getValue().equals(requiredSignals)
                        )
                        .findFirst();

        System.out.println();
        System.out.println("========================================");
        System.out.println(
                "Representative Pair: " + name
        );
        System.out.println("========================================");

        if (match.isEmpty()) {
            System.out.println(
                    "No pair found for this exact combination."
            );
            return;
        }

        CandidatePairGenerator.SessionPair pair =
                match.get().getKey();

        SessionBehavior first =
                sessions.get(pair.first());

        SessionBehavior second =
                sessions.get(pair.second());

        SimilarityResult similarity =
                similarityService.compare(
                        first,
                        second
                );

        printSession("Session A", first);
        printSession("Session B", second);

        System.out.println();
        System.out.println("Candidate-generation signals:");

        match.get()
                .getValue()
                .forEach(signal ->
                        System.out.println(
                                "  " + signal
                        )
                );

        printSimilarity(similarity);
    }

    private void printSession(
            String label,
            SessionBehavior session
    ) {

        System.out.println();
        System.out.println(label);
        System.out.println("----------------------------------------");

        System.out.println(
                "Session ID: " + session.sessionId()
        );

        System.out.println(
                "Source IP: " + session.sourceIp()
        );

        System.out.println(
                "Honeypot IP: " + session.honeypotIp()
        );

        System.out.println(
                "Sensor: " + session.sensor()
        );

        System.out.println(
                "First seen: " + session.firstSeen()
        );

        System.out.println(
                "Last seen: " + session.lastSeen()
        );

        System.out.println(
                "HASSH: " + session.hassh()
        );

        System.out.println(
                "Client version: " + session.clientVersion()
        );

        System.out.println(
                "Login success: " + session.loginSuccess()
        );

        System.out.println(
                "Login failure: " + session.loginFailure()
        );

        System.out.println(
                "Commands: " + session.commandSequence()
        );

        System.out.println(
                "File hashes: " + session.fileHashes()
        );

        System.out.println(
                "Download URLs: " + session.downloadUrls()
        );

        System.out.println(
                "Destination IPs: " + session.destinationIps()
        );

        System.out.println(
                "Destination ports: " + session.destinationPorts()
        );

        System.out.println(
                "Event sequence: " + session.eventSequence()
        );
    }

    private void printSimilarity(
            SimilarityResult similarity
    ) {

        System.out.println();
        System.out.println("Similarity comparison:");
        System.out.println("----------------------------------------");

        System.out.println(
                "Command similarity: "
                        + similarity.getCommandSimilarity()
        );

        System.out.println(
                "Event similarity: "
                        + similarity.getEventSimilarity()
        );

        System.out.println(
                "File hash similarity: "
                        + similarity.getFileHashSimilarity()
        );

        System.out.println(
                "HASSH similarity: "
                        + similarity.getHasshSimilarity()
        );

        System.out.println(
                "Client version similarity: "
                        + similarity.getClientVersionSimilarity()
        );

        System.out.println(
                "Download URL similarity: "
                        + similarity.getDownloadUrlSimilarity()
        );

        System.out.println(
                "Destination IP similarity: "
                        + similarity.getDestinationIpSimilarity()
        );

        System.out.println(
                "Destination port similarity: "
                        + similarity.getDestinationPortSimilarity()
        );

        System.out.println(
                "Login behavior similarity: "
                        + similarity.getLoginBehaviorSimilarity()
        );

        System.out.println(
                "Temporal distance: "
                        + similarity.getTemporalDistanceSeconds()
                        + " seconds"
        );

        System.out.println(
                "Similarity evidence: "
                        + similarity.getEvidence()
        );
    }
}