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

class SessionSimilarityPipelineTest {

    private final SessionSimilarityService similarityService =
            new SessionSimilarityService(
                    new SequenceSimilarityCalculator(),
                    new SetSimilarityCalculator(),
                    new ExactMatchSimilarityCalculator(),
                    new LoginBehaviorSimilarityCalculator()
            );

    @Test
    void shouldCompareTwoSessionBehaviorsProducedByThePipeline() {

        LocalDateTime firstTime =
                LocalDateTime.of(2026, 9, 27, 10, 0, 0);

        LocalDateTime secondTime =
                LocalDateTime.of(2026, 9, 27, 10, 2, 0);

        SessionBehavior first = new SessionBehavior(
                "session-1",
                "10.0.0.1",
                "10.0.0.100",
                "sensor-1",
                1,
                firstTime,
                firstTime.plusMinutes(5),

                List.of(
                        "cowrie.login.success",
                        "cowrie.command.input",
                        "cowrie.command.input",
                        "cowrie.session.closed"
                ),

                List.of(
                        "whoami",
                        "wget http://example.com/file"
                ),

                true,
                false,

                "hassh-1",
                "client-1",

                List.of(
                        "hash-1"
                ),

                List.of(
                        "http://example.com/file"
                ),

                List.of(
                        "8.8.8.8"
                ),

                List.of(
                        80
                )
        );

        SessionBehavior second = new SessionBehavior(
                "session-2",
                "10.0.0.2",
                "10.0.0.101",
                "sensor-2",
                2,
                secondTime,
                secondTime.plusMinutes(5),

                List.of(
                        "cowrie.login.success",
                        "cowrie.command.input",
                        "cowrie.command.input",
                        "cowrie.session.closed"
                ),

                List.of(
                        "whoami",
                        "wget http://example.com/file"
                ),

                true,
                false,

                "hassh-1",
                "client-1",

                List.of(
                        "hash-1"
                ),

                List.of(
                        "http://example.com/file"
                ),

                List.of(
                        "8.8.8.8"
                ),

                List.of(
                        80
                )
        );

        SimilarityResult result =
                similarityService.compare(first, second);

        assertEquals(
                1.0,
                result.getCommandSimilarity().similarity()
        );

        assertEquals(
                1.0,
                result.getEventSimilarity().similarity()
        );

        assertEquals(
                1.0,
                result.getFileHashSimilarity().similarity()
        );

        assertEquals(
                1.0,
                result.getHasshSimilarity().similarity()
        );

        assertEquals(
                1.0,
                result.getClientVersionSimilarity().similarity()
        );

        assertEquals(
                1.0,
                result.getDownloadUrlSimilarity().similarity()
        );

        assertEquals(
                1.0,
                result.getDestinationIpSimilarity().similarity()
        );

        assertEquals(
                1.0,
                result.getDestinationPortSimilarity().similarity()
        );

        assertEquals(
                1.0,
                result.getLoginBehaviorSimilarity().similarity()
        );

        assertEquals(
                120,
                result.getTemporalDistanceSeconds()
        );
    }
}