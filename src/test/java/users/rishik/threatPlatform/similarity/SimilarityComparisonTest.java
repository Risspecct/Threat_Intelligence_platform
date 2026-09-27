package users.rishik.threatPlatform.similarity;

import org.junit.jupiter.api.Test;
import users.rishik.threatPlatform.attack.dto.SessionBehavior;
import users.rishik.threatPlatform.similarity.calculator.ExactMatchSimilarityCalculator;
import users.rishik.threatPlatform.similarity.calculator.LoginBehaviorSimilarityCalculator;
import users.rishik.threatPlatform.similarity.calculator.SequenceSimilarityCalculator;
import users.rishik.threatPlatform.similarity.calculator.SetSimilarityCalculator;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SimilarityComparisonTest {

    private final SequenceSimilarityCalculator sequenceCalculator =
            new SequenceSimilarityCalculator();

    private final SetSimilarityCalculator setCalculator =
            new SetSimilarityCalculator();

    private final ExactMatchSimilarityCalculator exactMatchCalculator =
            new ExactMatchSimilarityCalculator();

    private final LoginBehaviorSimilarityCalculator loginCalculator =
            new LoginBehaviorSimilarityCalculator();

    @Test
    void identicalSessionsShouldHaveIdenticalCoreSignals() {

        SessionBehavior first = createSession(
                List.of("wget", "chmod", "./payload"),
                List.of("login.success", "command.input", "file.download"),
                List.of("hash-1", "hash-2"),
                "hassh-1"
        );

        SessionBehavior second = createSession(
                List.of("wget", "chmod", "./payload"),
                List.of("login.success", "command.input", "file.download"),
                List.of("hash-1", "hash-2"),
                "hassh-1"
        );

        assertEquals(
                1.0,
                sequenceCalculator.calculate(
                        first.commandSequence(),
                        second.commandSequence()
                )
        );

        assertEquals(
                1.0,
                sequenceCalculator.calculate(
                        first.eventSequence(),
                        second.eventSequence()
                )
        );

        assertEquals(
                1.0,
                setCalculator.calculate(
                        Set.copyOf(first.fileHashes()),
                        Set.copyOf(second.fileHashes())
                )
        );

        assertEquals(
                1.0,
                exactMatchCalculator.calculate(
                        first.hassh(),
                        second.hassh()
                )
        );
    }

    @Test
    void completelyDifferentSessionsShouldHaveNoCoreSimilarity() {

        SessionBehavior first = createSession(
                List.of("wget", "chmod"),
                List.of("login.success", "command.input"),
                List.of("hash-1"),
                "hassh-1"
        );

        SessionBehavior second = createSession(
                List.of("curl", "rm"),
                List.of("login.failure", "file.upload"),
                List.of("hash-2"),
                "hassh-2"
        );

        assertEquals(
                0.0,
                sequenceCalculator.calculate(
                        first.commandSequence(),
                        second.commandSequence()
                )
        );

        assertEquals(
                0.0,
                sequenceCalculator.calculate(
                        first.eventSequence(),
                        second.eventSequence()
                )
        );

        assertEquals(
                0.0,
                setCalculator.calculate(
                        Set.copyOf(first.fileHashes()),
                        Set.copyOf(second.fileHashes())
                )
        );

        assertEquals(
                0.0,
                exactMatchCalculator.calculate(
                        first.hassh(),
                        second.hassh()
                )
        );
    }

    @Test
    void partialCommandOverlapShouldProduceIntermediateSimilarity() {

        SessionBehavior first = createSession(
                List.of("wget", "chmod", "./payload"),
                List.of("login.success", "command.input"),
                List.of("hash-1"),
                "hassh-1"
        );

        SessionBehavior second = createSession(
                List.of("wget", "chmod", "whoami"),
                List.of("login.success", "command.input"),
                List.of("hash-2"),
                "hassh-2"
        );

        assertEquals(
                2.0 / 3.0,
                sequenceCalculator.calculate(
                        first.commandSequence(),
                        second.commandSequence()
                )
        );
    }

    @Test
    void sharedHashShouldBeDetectedEvenWhenCommandsDiffer() {

        SessionBehavior first = createSession(
                List.of("wget"),
                List.of("file.download"),
                List.of("shared-hash"),
                "hassh-1"
        );

        SessionBehavior second = createSession(
                List.of("curl"),
                List.of("command.input"),
                List.of("shared-hash"),
                "hassh-2"
        );

        assertEquals(
                0.0,
                sequenceCalculator.calculate(
                        first.commandSequence(),
                        second.commandSequence()
                )
        );

        assertEquals(
                1.0,
                setCalculator.calculate(
                        Set.copyOf(first.fileHashes()),
                        Set.copyOf(second.fileHashes())
                )
        );
    }

    @Test
    void matchingHasshAloneShouldBeSupportingEvidence() {

        SessionBehavior first = createSession(
                List.of("wget"),
                List.of("file.download"),
                List.of("hash-1"),
                "same-hassh"
        );

        SessionBehavior second = createSession(
                List.of("curl"),
                List.of("command.input"),
                List.of("hash-2"),
                "same-hassh"
        );

        assertEquals(
                1.0,
                exactMatchCalculator.calculate(
                        first.hassh(),
                        second.hassh()
                )
        );

        assertEquals(
                0.0,
                sequenceCalculator.calculate(
                        first.commandSequence(),
                        second.commandSequence()
                )
        );

        assertEquals(
                0.0,
                setCalculator.calculate(
                        Set.copyOf(first.fileHashes()),
                        Set.copyOf(second.fileHashes())
                )
        );
    }

    @Test
    void loginBehaviorShouldBeComparedSeparately() {

        SessionBehavior first = createSession(
                List.of(),
                List.of(),
                List.of(),
                "hassh-1"
        );

        SessionBehavior second = createSession(
                List.of(),
                List.of(),
                List.of(),
                "hassh-2"
        );

        assertEquals(
                1.0,
                loginCalculator.calculate(
                        first.loginSuccess() ? 1 : 0,
                        first.loginFailure() ? 1 : 0,
                        second.loginSuccess() ? 1 : 0,
                        second.loginFailure() ? 1 : 0
                )
        );
    }

    private SessionBehavior createSession(
            List<String> commands,
            List<String> events,
            List<String> hashes,
            String hassh
    ) {
        return new SessionBehavior(
                "session-1",
                "192.168.1.10",
                "10.0.0.1",
                "sensor-1",
                1,
                null,
                null,
                events,
                commands,
                true,
                false,
                hassh,
                "SSH-2.0-OpenSSH",
                hashes,
                List.of(),
                List.of(),
                List.of()
        );
    }
}