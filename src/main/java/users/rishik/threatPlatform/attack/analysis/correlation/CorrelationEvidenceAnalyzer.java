package users.rishik.threatPlatform.attack.analysis.correlation;

import users.rishik.threatPlatform.attack.dto.ThreatObservation;

import java.util.ArrayList;
import java.util.List;

public class CorrelationEvidenceAnalyzer {
    private final CorrelationEvidenceExtractor extractor = new CorrelationEvidenceExtractor();
    private final CorrelationEvidenceComparator comparator = new CorrelationEvidenceComparator();

    public CorrelationEvidenceResult analyze(
            ThreatObservation first,
            ThreatObservation second) {

        List<CorrelationEvidence> firstEvidence =
                extractor.extract(first);

        List<CorrelationEvidence> secondEvidence =
                extractor.extract(second);

        List<MatchedCorrelationEvidence> sharedEvidence =
                findSharedEvidence(firstEvidence, secondEvidence);

        TemporalCorrelation temporalCorrelation =
                TemporalCorrelation.between(
                        first.getTimestamp(),
                        second.getTimestamp()
                );

        return new CorrelationEvidenceResult(
                sharedEvidence,
                temporalCorrelation
        );
    }

    private List<MatchedCorrelationEvidence> findSharedEvidence(
            List<CorrelationEvidence> first,
            List<CorrelationEvidence> second) {

        List<MatchedCorrelationEvidence> shared = new ArrayList<>();

        for (CorrelationEvidence firstItem : first) {

            for (CorrelationEvidence secondItem : second) {

                double similarity =
                        comparator.compare(firstItem, secondItem);

                if (similarity > 0) {

                    shared.add(
                            new MatchedCorrelationEvidence(
                                    firstItem.type(),
                                    firstItem.value(),
                                    secondItem.value(),
                                    similarity
                            )
                    );

                    break;
                }
            }
        }

        return shared;
    }

    public double calculateEvidenceStrength(
            CorrelationEvidenceResult result) {

        if (result.sharedEvidence().isEmpty()) {
            return 0.0;
        }

        return result.sharedEvidence()
                .stream()
                .mapToDouble(MatchedCorrelationEvidence::similarity)
                .average()
                .orElse(0.0);
    }

    public long countStrongBehavioralEvidence(
            CorrelationEvidenceResult result) {

        return result.sharedEvidence()
                .stream()
                .filter(evidence ->
                        evidence.type().isStrongBehavioralEvidence())
                .count();
    }

    public long countContextualEvidence(
            CorrelationEvidenceResult result) {

        return result.sharedEvidence()
                .stream()
                .filter(evidence ->
                        evidence.type().isContextualEvidence())
                .count();
    }
}