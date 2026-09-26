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
    void shouldFinalizeSessionWhenClosedEventArrives() {

        SessionEventProcessor processor =
                new SessionEventProcessor(
                        new SessionBehaviorExtractor()
                );

        List<SessionBehavior> completed =
                new ArrayList<>();

        processor.accept(
                event(
                        "2025-06-27 23:09:31.000000",
                        "session-A",
                        "cowrie.login.success",
                        null
                ),
                completed::add
        );

        assertEquals(1, processor.activeSessionCount());
        assertEquals(0, completed.size());

        processor.accept(
                event(
                        "2025-06-27 23:09:33.000000",
                        "session-A",
                        "cowrie.command.input",
                        "whoami"
                ),
                completed::add
        );

        assertEquals(1, processor.activeSessionCount());
        assertEquals(0, completed.size());

        processor.accept(
                event(
                        "2025-06-27 23:09:35.000000",
                        "session-A",
                        "cowrie.session.closed",
                        null
                ),
                completed::add
        );

        assertEquals(0, processor.activeSessionCount());
        assertEquals(1, completed.size());

        SessionBehavior behavior = completed.getFirst();

        assertEquals("session-A", behavior.sessionId());
        assertTrue(behavior.loginSuccess());

        assertEquals(
                List.of("whoami"),
                behavior.commandSequence()
        );
    }

    @Test
    void shouldFinalizeSessionsWithoutClosedEventAtEnd() {

        SessionEventProcessor processor =
                new SessionEventProcessor(
                        new SessionBehaviorExtractor()
                );

        List<SessionBehavior> completed =
                new ArrayList<>();

        processor.accept(
                event(
                        "2025-06-27 23:09:31.000000",
                        "session-A",
                        "cowrie.login.success",
                        null
                ),
                completed::add
        );

        assertEquals(1, processor.activeSessionCount());
        assertEquals(0, completed.size());

        processor.finishRemaining(completed::add);

        assertEquals(0, processor.activeSessionCount());
        assertEquals(1, completed.size());

        assertEquals(
                "session-A",
                completed.getFirst().sessionId()
        );
    }

    @Test
    void shouldHandleInterleavedSessions() {

        SessionEventProcessor processor =
                new SessionEventProcessor(
                        new SessionBehaviorExtractor()
                );

        List<SessionBehavior> completed =
                new ArrayList<>();

        // A
        processor.accept(
                event(
                        "2025-06-27 23:09:31.000000",
                        "session-A",
                        "cowrie.login.success",
                        null
                ),
                completed::add
        );

        // B
        processor.accept(
                event(
                        "2025-06-27 23:09:32.000000",
                        "session-B",
                        "cowrie.login.failed",
                        null
                ),
                completed::add
        );

        // A closes
        processor.accept(
                event(
                        "2025-06-27 23:09:33.000000",
                        "session-A",
                        "cowrie.session.closed",
                        null
                ),
                completed::add
        );

        assertEquals(1, processor.activeSessionCount());
        assertEquals(1, completed.size());

        assertEquals(
                "session-A",
                completed.getFirst().sessionId()
        );

        // B closes
        processor.accept(
                event(
                        "2025-06-27 23:09:34.000000",
                        "session-B",
                        "cowrie.session.closed",
                        null
                ),
                completed::add
        );

        assertEquals(0, processor.activeSessionCount());
        assertEquals(2, completed.size());
    }

    private RawCowrieEvent event(
            String timestamp,
            String session,
            String eventId,
            String input
    ) {
        return new RawCowrieEvent(
                timestamp,
                null,
                null,
                null,
                eventId,
                session,
                "sensor-1",
                1,
                null,
                null,
                input,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                "source-1",
                "honeypot-1"
        );
    }
}