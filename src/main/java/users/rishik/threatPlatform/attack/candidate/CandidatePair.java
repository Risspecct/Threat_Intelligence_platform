package users.rishik.threatPlatform.attack.candidate;

public record CandidatePair(
        int first,
        int second
) {

    public CandidatePair {

        if (first > second) {
            throw new IllegalArgumentException(
                    "Candidate pair indexes must be ordered"
            );
        }
    }
}