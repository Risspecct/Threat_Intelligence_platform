package users.rishik.threatPlatform.attack;

import org.junit.jupiter.api.Test;
import users.rishik.threatPlatform.attack.dto.RawCowrieEvent;
import users.rishik.threatPlatform.attack.dto.SessionBehavior;
import users.rishik.threatPlatform.attack.service.SessionBehaviorExtractor;
import users.rishik.threatPlatform.attack.service.SessionEventProcessor;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SessionEventProcessorTest {

    @Test
    void shouldGroupInterleavedEventsBySession() {

        SessionEventProcessor processor =
                new SessionEventProcessor(
                        new SessionBehaviorExtractor()
                );

        // Session A - login
        processor.accept(event(
                "2025-06-27 23:09:31.000000",
                "session-A",
                "cowrie.login.success",
                null
        ));

        // Session B - login
        processor.accept(event(
                "2025-06-27 23:09:32.000000",
                "session-B",
                "cowrie.login.failed",
                null
        ));

        // Session A - command
        processor.accept(event(
                "2025-06-27 23:09:33.000000",
                "session-A",
                "cowrie.command.input",
                "whoami"
        ));

        // Session B - command
        processor.accept(event(
                "2025-06-27 23:09:34.000000",
                "session-B",
                "cowrie.command.input",
                "uname -a"
        ));

        assertEquals(2, processor.sessionCount());

        List<SessionBehavior> behaviors = new ArrayList<>();

        processor.finish(behaviors::add);

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
        assertFalse(sessionA.loginFailure());

        assertFalse(sessionB.loginSuccess());
        assertTrue(sessionB.loginFailure());

        assertEquals(
                List.of("whoami"),
                sessionA.commandSequence()
        );

        assertEquals(
                List.of("uname -a"),
                sessionB.commandSequence()
        );
    }

    private RawCowrieEvent event(
            String timestamp,
            String session,
            String eventId,
            String input
    ) {
        return new RawCowrieEvent(
                timestamp,
                null,              // srcPort
                null,              // dstIp
                null,              // dstPort
                eventId,
                session,
                "sensor-1",
                1,
                null,              // username
                null,              // password
                input,
                null,              // message
                null,              // url
                null,              // protocol
                null,              // hassh
                null,              // hasshAlgorithms
                null,              // fingerprint
                null,              // filename
                null,              // destfile
                null,              // outfile
                null,              // shasum
                null,              // size
                null,              // duration
                null,              // version
                "source-1",
                "honeypot-1"
        );
    }
}