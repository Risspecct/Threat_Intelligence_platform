package users.rishik.threatPlatform.attack.service;

import users.rishik.threatPlatform.attack.dto.RawCowrieEvent;
import users.rishik.threatPlatform.attack.dto.SessionBehavior;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

public class SessionEventProcessor {

    private static final String SESSION_CLOSED =
            "cowrie.session.closed";

    private final Map<String, SessionAccumulator> activeSessions =
            new HashMap<>();

    private final SessionBehaviorExtractor extractor;

    public SessionEventProcessor(SessionBehaviorExtractor extractor) {
        this.extractor = extractor;
    }

    public void accept(
            RawCowrieEvent event,
            Consumer<SessionBehavior> consumer
    ) {

        if (event.session() == null || event.session().isBlank()) {
            return;
        }

        String sessionId = event.session();

        SessionAccumulator accumulator =
                activeSessions.computeIfAbsent(
                        sessionId,
                        ignored -> new SessionAccumulator()
                );

        accumulator.add(event);

        if (SESSION_CLOSED.equals(event.eventid())) {
            finishSession(sessionId, consumer);
        }
    }

    public void finishRemaining(
            Consumer<SessionBehavior> consumer
    ) {

        for (Map.Entry<String, SessionAccumulator> entry
                : activeSessions.entrySet()) {

            consumer.accept(
                    entry.getValue().build(extractor)
            );
        }

        activeSessions.clear();
    }

    public int activeSessionCount() {
        return activeSessions.size();
    }

    private void finishSession(
            String sessionId,
            Consumer<SessionBehavior> consumer
    ) {

        SessionAccumulator accumulator =
                activeSessions.remove(sessionId);

        if (accumulator != null) {
            consumer.accept(
                    accumulator.build(extractor)
            );
        }
    }
}