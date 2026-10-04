package users.rishik.threatPlatform.attack.analysis.correlation;

public class CorrelationEvidenceComparator {

    private final TextEvidenceSimilarity textSimilarity =
            new TextEvidenceSimilarity();

    public double compare(
            CorrelationEvidence first,
            CorrelationEvidence second) {

        if (first.type() != second.type()) {
            return 0.0;
        }

        return switch (first.type()) {

            case COMMAND ->
                    textSimilarity.lcsSimilarity(
                            first.value(),
                            second.value()
                    );

            default ->
                    first.value().equals(second.value())
                            ? 1.0
                            : 0.0;
        };
    }
}