package users.rishik.threatPlatform.attack.candidate;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;

public class NonCandidatePairSampler {

    public List<CandidatePair> sample(
            int sessionCount,
            Set<CandidatePair> candidatePairs,
            int sampleSize,
            long seed
    ) {

        if (sessionCount < 2) {
            throw new IllegalArgumentException(
                    "At least two sessions are required"
            );
        }

        if (sampleSize < 0) {
            throw new IllegalArgumentException(
                    "Sample size cannot be negative"
            );
        }

        long totalPairs =
                (long) sessionCount
                        * (sessionCount - 1)
                        / 2;

        long availableNonCandidatePairs =
                totalPairs - candidatePairs.size();

        if (sampleSize > availableNonCandidatePairs) {
            throw new IllegalArgumentException(
                    "Requested sample is larger than the available " +
                            "non-candidate pairs"
            );
        }

        Random random = new Random(seed);

        Set<CandidatePair> sampledPairs =
                new HashSet<>();

        while (sampledPairs.size() < sampleSize) {

            int first = random.nextInt(sessionCount);
            int second = random.nextInt(sessionCount);

            if (first == second) {
                continue;
            }

            if (first > second) {
                int temp = first;
                first = second;
                second = temp;
            }

            CandidatePair pair =
                    new CandidatePair(first, second);

            if (candidatePairs.contains(pair)) {
                continue;
            }

            sampledPairs.add(pair);
        }

        return new ArrayList<>(sampledPairs);
    }
}