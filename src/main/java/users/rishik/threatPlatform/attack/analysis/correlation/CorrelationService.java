package users.rishik.threatPlatform.attack.analysis.correlation;

import org.springframework.stereotype.Service;
import users.rishik.threatPlatform.attack.dto.ThreatObservation;

@Service
public class CorrelationService {

    private final CorrelationEvidenceAnalyzer analyzer =
            new CorrelationEvidenceAnalyzer();

    public CorrelationEvidenceResult correlate(
            ThreatObservation first,
            ThreatObservation second) {

        return analyzer.analyze(first, second);
    }
}