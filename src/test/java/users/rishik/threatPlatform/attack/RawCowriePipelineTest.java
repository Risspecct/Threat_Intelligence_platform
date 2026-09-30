package users.rishik.threatPlatform.attack;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import users.rishik.threatPlatform.attack.dto.SessionBehavior;
import users.rishik.threatPlatform.attack.service.RawCowrieEventReader;
import users.rishik.threatPlatform.attack.service.SessionBehaviorExtractor;
import users.rishik.threatPlatform.attack.service.SessionEventProcessor;
import users.rishik.threatPlatform.similarity.calculator.ExactMatchSimilarityCalculator;
import users.rishik.threatPlatform.similarity.calculator.LoginBehaviorSimilarityCalculator;
import users.rishik.threatPlatform.similarity.calculator.SequenceSimilarityCalculator;
import users.rishik.threatPlatform.similarity.calculator.SetSimilarityCalculator;
import users.rishik.threatPlatform.similarity.model.SimilarityResult;
import users.rishik.threatPlatform.similarity.service.SessionSimilarityService;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class RawCowriePipelineTest {

    @Test
    void shouldReadAndProcessInterleavedJsonlSessions() throws Exception {

        Path file = Files.createTempFile(
                "cowrie-pipeline-",
                ".jsonl"
        );

        String content = """
                {"ts":"2025-06-27 23:09:31.000000","eventid":"cowrie.login.success","session":"session-A","sensor":"sensor-1","group":1,"src_ip":"source-A","honeypot_ip":"honeypot-1"}
                {"ts":"2025-06-27 23:09:32.000000","eventid":"cowrie.login.failed","session":"session-B","sensor":"sensor-1","group":1,"src_ip":"source-B","honeypot_ip":"honeypot-1"}
                {"ts":"2025-06-27 23:09:33.000000","eventid":"cowrie.command.input","session":"session-A","sensor":"sensor-1","group":1,"input":"whoami","src_ip":"source-A","honeypot_ip":"honeypot-1"}
                {"ts":"2025-06-27 23:09:34.000000","eventid":"cowrie.session.closed","session":"session-A","sensor":"sensor-1","group":1,"src_ip":"source-A","honeypot_ip":"honeypot-1"}
                {"ts":"2025-06-27 23:09:35.000000","eventid":"cowrie.command.input","session":"session-B","sensor":"sensor-1","group":1,"input":"uname -a","src_ip":"source-B","honeypot_ip":"honeypot-1"}
                {"ts":"2025-06-27 23:09:36.000000","eventid":"cowrie.session.closed","session":"session-B","sensor":"sensor-1","group":1,"src_ip":"source-B","honeypot_ip":"honeypot-1"}
                """;

        try {
            Files.writeString(file, content);

            RawCowrieEventReader reader =
                    new RawCowrieEventReader(new ObjectMapper());

            SessionEventProcessor processor =
                    new SessionEventProcessor(
                            new SessionBehaviorExtractor()
                    );

            SessionSimilarityService similarityService =
                    new SessionSimilarityService(
                            new SequenceSimilarityCalculator(),
                            new SetSimilarityCalculator(),
                            new ExactMatchSimilarityCalculator(),
                            new LoginBehaviorSimilarityCalculator()
                    );

            List<SessionBehavior> behaviors =
                    new ArrayList<>();

            reader.read(
                    file,
                    event -> processor.accept(
                            event,
                            behaviors::add
                    )
            );

            processor.finishRemaining(behaviors::add);

            // ---------------------------------------------------------
            // Verify raw pipeline
            // ---------------------------------------------------------

            assertEquals(2, behaviors.size());

            SessionBehavior sessionA = behaviors.stream()
                    .filter(b -> b.sessionId().equals("session-A"))
                    .findFirst()
                    .orElseThrow();

            SessionBehavior sessionB = behaviors.stream()
                    .filter(b -> b.sessionId().equals("session-B"))
                    .findFirst()
                    .orElseThrow();

            assertTrue(sessionA.loginSuccess());

            assertEquals(
                    List.of("whoami"),
                    sessionA.commandSequence()
            );

            assertTrue(sessionB.loginFailure());

            assertEquals(
                    List.of("uname -a"),
                    sessionB.commandSequence()
            );

            // ---------------------------------------------------------
            // Verify similarity pipeline
            // ---------------------------------------------------------

            SimilarityResult result =
                    similarityService.compare(
                            sessionA,
                            sessionB
                    );

            // Command sequences:
            // [whoami]
            // [uname -a]
            //
            // LCS = 0
            // similarity = 0 / 1 = 0
            assertEquals(
                    0.0,
                    result.getCommandSimilarity().similarity()
            );

            // Event sequences:
            //
            // session-A:
            // [login.success, command.input, session.closed]
            //
            // session-B:
            // [login.failed, command.input, session.closed]
            //
            // LCS = [command.input, session.closed] = 2
            // max length = 3
            // similarity = 2 / 3
            assertEquals(
                    2.0 / 3.0,
                    result.getEventSimilarity().similarity()
            );

            // No file hashes were supplied.
            // Empty set vs empty set = 1.0
            assertEquals(
                    1.0,
                    result.getFileHashSimilarity().similarity()
            );

            // No HASSH values were supplied.
            // Both values are absent, so this is not comparable evidence.
            assertEquals(
                    1.0,
                    result.getHasshSimilarity().similarity()
            );

            // No client versions were supplied.
            assertEquals(
                    1.0,
                    result.getClientVersionSimilarity().similarity()
            );

            // No download URLs were supplied.
            // Empty set vs empty set = 1.0
            assertEquals(
                    1.0,
                    result.getDownloadUrlSimilarity().similarity()
            );

            // No destination IPs were supplied.
            assertEquals(
                    1.0,
                    result.getDestinationIpSimilarity().similarity()
            );

            // No destination ports were supplied.
            assertEquals(
                    1.0,
                    result.getDestinationPortSimilarity().similarity()
            );

            // session-A:
            // success = true, failure = false
            //
            // session-B:
            // success = false, failure = true
            //
            // Completely different login behavior = 0.0
            assertEquals(
                    0.0,
                    result.getLoginBehaviorSimilarity().similarity()
            );

            // First events:
            // session-A = 23:09:31
            // session-B = 23:09:32
            //
            // Difference = 1 second
            assertEquals(
                    1,
                    result.getTemporalDistanceSeconds()
            );
        } finally {
            Files.deleteIfExists(file);
        }
    }
}
