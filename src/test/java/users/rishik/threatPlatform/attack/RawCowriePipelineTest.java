package users.rishik.threatPlatform.attack;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import users.rishik.threatPlatform.attack.dto.SessionBehavior;
import users.rishik.threatPlatform.attack.service.RawCowrieEventReader;
import users.rishik.threatPlatform.attack.service.SessionBehaviorExtractor;
import users.rishik.threatPlatform.attack.service.SessionEventProcessor;

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

        } finally {
            Files.deleteIfExists(file);
        }
    }
}