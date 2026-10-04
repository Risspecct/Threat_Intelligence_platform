package users.rishik.threatPlatform.correlation;

import org.junit.jupiter.api.Test;
import users.rishik.threatPlatform.attack.analysis.correlation.CorrelationEvidence;
import users.rishik.threatPlatform.attack.analysis.correlation.CorrelationEvidenceComparator;
import users.rishik.threatPlatform.attack.analysis.correlation.CorrelationEvidenceType;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CorrelationEvidenceComparatorTest {

    private final CorrelationEvidenceComparator comparator =
            new CorrelationEvidenceComparator();

    @Test
    void exactEvidenceShouldReturnOne() {

        CorrelationEvidence first =
                new CorrelationEvidence(
                        CorrelationEvidenceType.FILE_HASH,
                        "hash-123"
                );

        CorrelationEvidence second =
                new CorrelationEvidence(
                        CorrelationEvidenceType.FILE_HASH,
                        "hash-123"
                );

        assertEquals(
                1.0,
                comparator.compare(first, second)
        );
    }

    @Test
    void differentExactEvidenceShouldReturnZero() {

        CorrelationEvidence first =
                new CorrelationEvidence(
                        CorrelationEvidenceType.DESTINATION_PORT,
                        "22"
                );

        CorrelationEvidence second =
                new CorrelationEvidence(
                        CorrelationEvidenceType.DESTINATION_PORT,
                        "80"
                );

        assertEquals(
                0.0,
                comparator.compare(first, second)
        );
    }

    @Test
    void similarCommandsShouldReturnPartialSimilarity() {

        CorrelationEvidence first =
                new CorrelationEvidence(
                        CorrelationEvidenceType.COMMAND,
                        "wget http://example.com/a"
                );

        CorrelationEvidence second =
                new CorrelationEvidence(
                        CorrelationEvidenceType.COMMAND,
                        "wget http://example.com/b"
                );

        assertEquals(
                0.96,
                comparator.compare(first, second),
                0.001
        );
    }
}
