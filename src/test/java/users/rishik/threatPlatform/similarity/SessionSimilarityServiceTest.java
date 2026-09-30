package users.rishik.threatPlatform.similarity;

import org.junit.jupiter.api.Test;
import users.rishik.threatPlatform.attack.dto.SessionBehavior;
import users.rishik.threatPlatform.similarity.calculator.ExactMatchSimilarityCalculator;
import users.rishik.threatPlatform.similarity.calculator.LoginBehaviorSimilarityCalculator;
import users.rishik.threatPlatform.similarity.calculator.SequenceSimilarityCalculator;
import users.rishik.threatPlatform.similarity.calculator.SetSimilarityCalculator;
import users.rishik.threatPlatform.similarity.model.SimilarityResult;
import users.rishik.threatPlatform.similarity.service.SessionSimilarityService;

import java.time.LocalDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SessionSimilarityServiceTest {

    private final SessionSimilarityService service =
            new SessionSimilarityService(
                    new SequenceSimilarityCalculator(),
                    new SetSimilarityCalculator(),
                    new ExactMatchSimilarityCalculator(),
                    new LoginBehaviorSimilarityCalculator()
            );

    @Test
    void shouldCalculateSimilarityAcrossAllFeatures() {

        LocalDateTime time =
                LocalDateTime.of(2026, 9, 27, 10, 0);

        SessionBehavior first = new SessionBehavior(
                "session-1",
                "10.0.0.1",
                "10.0.0.100",
                "sensor-1",
                1,
                time,
                time.plusMinutes(5),
                List.of("login", "command", "download"),
                List.of("whoami", "wget"),
                true,
                false,
                "hassh-1",
                "client-1",
                List.of("hash-1", "hash-2"),
                List.of("http://example.com/file"),
                List.of("8.8.8.8"),
                List.of(80)
        );

        SessionBehavior second = new SessionBehavior(
                "session-2",
                "10.0.0.2",
                "10.0.0.101",
                "sensor-2",
                2,
                time.plusSeconds(120),
                time.plusMinutes(6),
                List.of("login", "command", "download"),
                List.of("whoami", "wget"),
                true,
                false,
                "hassh-1",
                "client-1",
                List.of("hash-1", "hash-2"),
                List.of("http://example.com/file"),
                List.of("8.8.8.8"),
                List.of(80)
        );

        SimilarityResult result =
                service.compare(first, second);

        assertEquals(1.0, result.getCommandSimilarity().similarity());
        assertEquals(1.0, result.getEventSimilarity().similarity());
        assertEquals(1.0, result.getFileHashSimilarity().similarity());
        assertEquals(1.0, result.getHasshSimilarity().similarity());
        assertEquals(1.0, result.getClientVersionSimilarity().similarity());
        assertEquals(1.0, result.getDownloadUrlSimilarity().similarity());
        assertEquals(1.0, result.getDestinationIpSimilarity().similarity());
        assertEquals(1.0, result.getDestinationPortSimilarity().similarity());
        assertEquals(1.0, result.getLoginBehaviorSimilarity().similarity());

        assertEquals(120, result.getTemporalDistanceSeconds());
    }

    @Test
    void shouldReturnLowSimilarityForDifferentSessions() {

        LocalDateTime time =
                LocalDateTime.of(2026, 9, 27, 10, 0);

        SessionBehavior first = new SessionBehavior(
                "session-1",
                "10.0.0.1",
                "10.0.0.100",
                "sensor-1",
                1,
                time,
                time.plusMinutes(5),
                List.of("login", "command", "download"),
                List.of("whoami", "wget"),
                true,
                false,
                "hassh-1",
                "client-1",
                List.of("hash-1"),
                List.of("http://example.com/file"),
                List.of("8.8.8.8"),
                List.of(80)
        );

        SessionBehavior second = new SessionBehavior(
                "session-2",
                "10.0.0.2",
                "10.0.0.101",
                "sensor-2",
                2,
                time.plusSeconds(300),
                time.plusMinutes(6),
                List.of("login", "command", "upload"),
                List.of("uname", "curl"),
                false,
                true,
                "hassh-2",
                "client-2",
                List.of("hash-2"),
                List.of("http://malicious.example/payload"),
                List.of("192.168.1.10"),
                List.of(443)
        );

        SimilarityResult result =
                service.compare(first, second);

        assertEquals(0.0, result.getCommandSimilarity().similarity());
        assertEquals(2.0 / 3.0, result.getEventSimilarity().similarity());
        assertEquals(0.0, result.getFileHashSimilarity().similarity());
        assertEquals(0.0, result.getHasshSimilarity().similarity());
        assertEquals(0.0, result.getClientVersionSimilarity().similarity());
        assertEquals(0.0, result.getDownloadUrlSimilarity().similarity());
        assertEquals(0.0, result.getDestinationIpSimilarity().similarity());
        assertEquals(0.0, result.getDestinationPortSimilarity().similarity());
        assertEquals(0.0, result.getLoginBehaviorSimilarity().similarity());

        assertEquals(300, result.getTemporalDistanceSeconds());
    }

    @Test
    void shouldCalculatePartialSimilarity() {

        LocalDateTime time =
                LocalDateTime.of(2026, 9, 27, 10, 0);

        SessionBehavior first = new SessionBehavior(
                "session-1",
                "10.0.0.1",
                "10.0.0.100",
                "sensor-1",
                1,
                time,
                time.plusMinutes(5),
                List.of("login", "command", "download", "command"),
                List.of("whoami", "wget", "chmod"),
                true,
                false,
                "hassh-1",
                "client-1",
                List.of("hash-1", "hash-2"),
                List.of("http://example.com/file"),
                List.of("8.8.8.8", "1.1.1.1"),
                List.of(80, 443)
        );

        SessionBehavior second = new SessionBehavior(
                "session-2",
                "10.0.0.2",
                "10.0.0.101",
                "sensor-2",
                2,
                time.plusSeconds(60),
                time.plusMinutes(6),
                List.of("login", "command", "upload"),
                List.of("whoami", "curl"),
                true,
                false,
                "hassh-1",
                "client-2",
                List.of("hash-2", "hash-3"),
                List.of("http://example.com/file"),
                List.of("8.8.8.8"),
                List.of(80)
        );

        SimilarityResult result =
                service.compare(first, second);

        assertEquals(
                1.0 / 3.0,
                result.getCommandSimilarity().similarity()
        );

        assertEquals(
                2.0 / 4.0,
                result.getEventSimilarity().similarity()
        );

        assertEquals(
                1.0 / 3.0,
                result.getFileHashSimilarity().similarity()
        );

        assertEquals(1.0, result.getHasshSimilarity().similarity());

        assertEquals(0.0, result.getClientVersionSimilarity().similarity());

        assertEquals(1.0, result.getDownloadUrlSimilarity().similarity());

        assertEquals(
                1.0 / 2.0,
                result.getDestinationIpSimilarity().similarity()
        );

        assertEquals(
                1.0 / 2.0,
                result.getDestinationPortSimilarity().similarity()
        );

        assertEquals(1.0, result.getLoginBehaviorSimilarity().similarity());

        assertEquals(60, result.getTemporalDistanceSeconds());
    }
}