package users.rishik.threatPlatform.similarity;

import org.junit.jupiter.api.Test;
import users.rishik.threatPlatform.attack.dto.SessionBehavior;
import users.rishik.threatPlatform.similarity.calculator.ExactMatchSimilarityCalculator;
import users.rishik.threatPlatform.similarity.calculator.LoginBehaviorSimilarityCalculator;
import users.rishik.threatPlatform.similarity.calculator.SequenceSimilarityCalculator;
import users.rishik.threatPlatform.similarity.calculator.SetSimilarityCalculator;
import users.rishik.threatPlatform.similarity.model.FeatureSimilarity;
import users.rishik.threatPlatform.similarity.model.SimilarityResult;
import users.rishik.threatPlatform.similarity.service.SessionSimilarityService;

import java.time.LocalDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FeatureComparabilityTest {

    private final SessionSimilarityService service = new SessionSimilarityService(
            new SequenceSimilarityCalculator(), new SetSimilarityCalculator(),
            new ExactMatchSimilarityCalculator(), new LoginBehaviorSimilarityCalculator());

    @Test
    void shouldRejectSimilarityOutsideUnitInterval() {
        assertThrows(IllegalArgumentException.class, () -> new FeatureSimilarity(-0.1, true));
        assertThrows(IllegalArgumentException.class, () -> new FeatureSimilarity(1.1, true));
    }

    @Test
    void shouldMarkSequenceComparabilityOnlyWhenBothSequencesContainValues() {
        assertSimilarity(1.0, false, service.compare(session(List.of(), List.of(), null, false, false),
                session(List.of(), List.of(), null, false, false)).getCommandSimilarity());
        assertSimilarity(0.0, false, service.compare(session(List.of(), List.of(), null, false, false),
                session(List.of("A"), List.of(), null, false, false)).getCommandSimilarity());
        assertSimilarity(0.5, true, service.compare(session(List.of("A", "B"), List.of(), null, false, false),
                session(List.of("A", "C"), List.of(), null, false, false)).getCommandSimilarity());
    }

    @Test
    void shouldMarkSetComparabilityOnlyWhenBothSetsContainValues() {
        assertSimilarity(1.0, false, service.compare(session(List.of(), List.of(), null, false, false),
                session(List.of(), List.of(), null, false, false)).getFileHashSimilarity());
        assertSimilarity(0.0, false, service.compare(session(List.of(), List.of(), null, false, false),
                session(List.of(), List.of("A"), null, false, false)).getFileHashSimilarity());
        assertSimilarity(1.0 / 3.0, true, service.compare(session(List.of(), List.of("A", "B"), null, false, false),
                session(List.of(), List.of("B", "C"), null, false, false)).getFileHashSimilarity());
    }

    @Test
    void shouldTreatNullAndBlankExactValuesAsAbsent() {
        assertSimilarity(1.0, false, service.compare(session(List.of(), List.of(), null, false, false),
                session(List.of(), List.of(), " ", false, false)).getHasshSimilarity());
        assertSimilarity(0.0, false, service.compare(session(List.of(), List.of(), null, false, false),
                session(List.of(), List.of(), "abc", false, false)).getHasshSimilarity());
        assertSimilarity(1.0, true, service.compare(session(List.of(), List.of(), "abc", false, false),
                session(List.of(), List.of(), "abc", false, false)).getHasshSimilarity());
        assertSimilarity(0.0, true, service.compare(session(List.of(), List.of(), "abc", false, false),
                session(List.of(), List.of(), "xyz", false, false)).getHasshSimilarity());
    }

    @Test
    void shouldMarkLoginBehaviorComparableOnlyWhenBothSessionsHaveActivity() {
        assertSimilarity(1.0, false, service.compare(session(List.of(), List.of(), null, false, false),
                session(List.of(), List.of(), null, false, false)).getLoginBehaviorSimilarity());
        assertSimilarity(0.0, false, service.compare(session(List.of(), List.of(), null, true, false),
                session(List.of(), List.of(), null, false, false)).getLoginBehaviorSimilarity());
        assertSimilarity(1.0, true, service.compare(session(List.of(), List.of(), null, true, false),
                session(List.of(), List.of(), null, true, false)).getLoginBehaviorSimilarity());
    }

    @Test
    void shouldNotTreatTwoSessionsWithoutBehavioralFeaturesAsComparableEvidence() {
        SimilarityResult result = service.compare(
                session(List.of(), List.of(), null, false, false),
                session(List.of(), List.of(), null, false, false));

        assertFalse(result.getCommandSimilarity().comparable());
        assertFalse(result.getEventSimilarity().comparable());
        assertFalse(result.getFileHashSimilarity().comparable());
        assertFalse(result.getHasshSimilarity().comparable());
        assertFalse(result.getClientVersionSimilarity().comparable());
        assertFalse(result.getDownloadUrlSimilarity().comparable());
        assertFalse(result.getDestinationIpSimilarity().comparable());
        assertFalse(result.getDestinationPortSimilarity().comparable());
        assertFalse(result.getLoginBehaviorSimilarity().comparable());
        assertEquals(1.0, result.getCommandSimilarity().similarity());
        assertEquals(1.0, result.getFileHashSimilarity().similarity());
        assertEquals(1.0, result.getHasshSimilarity().similarity());
    }

    private void assertSimilarity(double expectedSimilarity, boolean expectedComparable,
                                  FeatureSimilarity actual) {
        assertEquals(expectedSimilarity, actual.similarity(), 0.000001);
        assertEquals(expectedComparable, actual.comparable());
    }

    private SessionBehavior session(List<String> commands, List<String> hashes, String hassh,
                                    boolean loginSuccess, boolean loginFailure) {
        LocalDateTime time = LocalDateTime.of(2025, 1, 1, 0, 0);
        return new SessionBehavior("session", "source", "honeypot", "sensor", 1, time, time,
                List.of(), commands, loginSuccess, loginFailure, hassh, null, hashes, List.of(),
                List.of(), List.of());
    }
}
