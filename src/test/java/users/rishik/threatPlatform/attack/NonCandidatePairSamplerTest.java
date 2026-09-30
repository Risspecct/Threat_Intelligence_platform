package users.rishik.threatPlatform.attack;

import org.junit.jupiter.api.Test;
import users.rishik.threatPlatform.attack.candidate.CandidatePair;
import users.rishik.threatPlatform.attack.candidate.NonCandidatePairSampler;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class NonCandidatePairSamplerTest {

    private final NonCandidatePairSampler sampler =
            new NonCandidatePairSampler();

    @Test
    void shouldSampleRequestedNumberOfNonCandidatePairs() {

        Set<CandidatePair> candidates = Set.of(
                new CandidatePair(0, 1),
                new CandidatePair(2, 3),
                new CandidatePair(4, 5)
        );

        List<CandidatePair> sampled =
                sampler.sample(
                        10,
                        candidates,
                        20,
                        42
                );

        assertEquals(20, sampled.size());

        assertTrue(
                sampled.stream()
                        .noneMatch(candidates::contains)
        );
    }

    @Test
    void shouldNotProduceSelfPairs() {

        List<CandidatePair> sampled =
                sampler.sample(
                        20,
                        Set.of(),
                        50,
                        42
                );

        assertTrue(
                sampled.stream()
                        .noneMatch(
                                pair -> pair.first() == pair.second()
                        )
        );
    }

    @Test
    void shouldNotProduceDuplicatePairs() {

        List<CandidatePair> sampled =
                sampler.sample(
                        20,
                        Set.of(),
                        50,
                        42
                );

        assertEquals(
                sampled.size(),
                Set.copyOf(sampled).size()
        );
    }

    @Test
    void shouldProduceCanonicalPairs() {

        List<CandidatePair> sampled =
                sampler.sample(
                        20,
                        Set.of(),
                        50,
                        42
                );

        assertTrue(
                sampled.stream()
                        .allMatch(
                                pair -> pair.first() < pair.second()
                        )
        );
    }

    @Test
    void shouldBeReproducibleWithSameSeed() {

        List<CandidatePair> first =
                sampler.sample(
                        100,
                        Set.of(),
                        100,
                        42
                );

        List<CandidatePair> second =
                sampler.sample(
                        100,
                        Set.of(),
                        100,
                        42
                );

        assertEquals(first, second);
    }

    @Test
    void shouldRejectImpossibleSampleSize() {

        Set<CandidatePair> candidates = Set.of(
                new CandidatePair(0, 1),
                new CandidatePair(0, 2),
                new CandidatePair(1, 2)
        );

        assertThrows(
                IllegalArgumentException.class,
                () -> sampler.sample(
                        3,
                        candidates,
                        1,
                        42
                )
        );
    }
}