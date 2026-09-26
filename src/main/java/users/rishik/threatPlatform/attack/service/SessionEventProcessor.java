package users.rishik.threatPlatform.attack.service;

import users.rishik.threatPlatform.attack.dto.RawCowrieEvent;
import users.rishik.threatPlatform.attack.dto.SessionBehavior;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

public class SessionEventProcessor {

    private final Map<String, SessionAccumulator> sessions =
            new HashMap<>();

    private final SessionBehaviorExtractor extractor;

    public SessionEventProcessor(SessionBehaviorExtractor extractor) {
        this.extractor = extractor;
    }

    public void accept(RawCowrieEvent event) {

        if (event.session() == null || event.session().isBlank()) {
            return;
        }

        sessions.computeIfAbsent(
                        event.session(),
                        ignored -> new SessionAccumulator()
                )
                .add(event);
    }

    public void finish(Consumer<SessionBehavior> consumer) {

        for (SessionAccumulator accumulator : sessions.values()) {
            consumer.accept(accumulator.build(extractor));
        }

        sessions.clear();
    }

    public int sessionCount() {
        return sessions.size();
    }
}