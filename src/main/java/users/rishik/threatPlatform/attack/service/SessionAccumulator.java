package users.rishik.threatPlatform.attack.service;

import users.rishik.threatPlatform.attack.dto.RawCowrieEvent;
import users.rishik.threatPlatform.attack.dto.SessionBehavior;

import java.util.ArrayList;
import java.util.List;

public class SessionAccumulator {

    private final List<RawCowrieEvent> events = new ArrayList<>();

    public void add(RawCowrieEvent event) {
        events.add(event);
    }

    public int size() {
        return events.size();
    }

    public SessionBehavior build(SessionBehaviorExtractor extractor) {
        if (events.isEmpty()) {
            throw new IllegalStateException("Cannot build behavior from empty session");
        }

        return extractor.extract(events);
    }
}