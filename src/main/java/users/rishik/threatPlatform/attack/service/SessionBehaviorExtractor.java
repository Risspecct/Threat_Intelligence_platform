package users.rishik.threatPlatform.attack.service;

import users.rishik.threatPlatform.attack.dto.RawCowrieEvent;
import users.rishik.threatPlatform.attack.dto.SessionBehavior;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Comparator;
import java.util.List;

public class SessionBehaviorExtractor {

    private static final DateTimeFormatter TIMESTAMP_FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSSSSS");

    public SessionBehavior extract(List<RawCowrieEvent> events) {

        if (events == null || events.isEmpty()) {
            throw new IllegalArgumentException("Session must contain at least one event");
        }

        List<RawCowrieEvent> sortedEvents = events.stream()
                .sorted(Comparator.comparing(
                        event -> parseTimestamp(event.ts())
                ))
                .toList();

        RawCowrieEvent firstEvent = sortedEvents.getFirst();

        List<String> eventSequence = sortedEvents.stream()
                .map(RawCowrieEvent::eventid)
                .filter(eventId -> eventId != null)
                .toList();

        List<String> commandSequence = sortedEvents.stream()
                .filter(event -> "cowrie.command.input".equals(event.eventid()))
                .map(RawCowrieEvent::input)
                .filter(input -> input != null && !input.isBlank())
                .toList();

        boolean loginSuccess = sortedEvents.stream()
                .anyMatch(event ->
                        "cowrie.login.success".equals(event.eventid())
                );

        boolean loginFailure = sortedEvents.stream()
                .anyMatch(event ->
                        "cowrie.login.failed".equals(event.eventid())
                );

        String hassh = firstNonNull(
                sortedEvents.stream()
                        .map(RawCowrieEvent::hassh)
                        .filter(value -> value != null && !value.isBlank())
                        .toList()
        );

        String clientVersion = firstNonNull(
                sortedEvents.stream()
                        .map(RawCowrieEvent::version)
                        .filter(value -> value != null && !value.isBlank())
                        .toList()
        );

        List<String> fileHashes = sortedEvents.stream()
                .map(RawCowrieEvent::shasum)
                .filter(value -> value != null && !value.isBlank())
                .distinct()
                .toList();

        List<String> downloadUrls = sortedEvents.stream()
                .map(RawCowrieEvent::url)
                .filter(value -> value != null && !value.isBlank())
                .distinct()
                .toList();

        List<String> destinationIps = sortedEvents.stream()
                .map(RawCowrieEvent::dstIp)
                .filter(value -> value != null && !value.isBlank())
                .distinct()
                .toList();

        List<Integer> destinationPorts = sortedEvents.stream()
                .map(RawCowrieEvent::dstPort)
                .filter(value -> value != null)
                .distinct()
                .toList();

        return new SessionBehavior(
                firstEvent.session(),
                firstEvent.srcIp(),
                firstEvent.honeypotIp(),
                firstEvent.sensor(),
                firstEvent.group(),
                parseTimestamp(sortedEvents.getFirst().ts()),
                parseTimestamp(sortedEvents.getLast().ts()),
                eventSequence,
                commandSequence,
                loginSuccess,
                loginFailure,
                hassh,
                clientVersion,
                fileHashes,
                downloadUrls,
                destinationIps,
                destinationPorts
        );
    }

    private LocalDateTime parseTimestamp(String timestamp) {

        if (timestamp == null || timestamp.isBlank()) {
            throw new IllegalArgumentException("Event timestamp cannot be null or blank");
        }

        return LocalDateTime.parse(timestamp, TIMESTAMP_FORMATTER);
    }

    private String firstNonNull(List<String> values) {
        return values.isEmpty() ? null : values.getFirst();
    }
}