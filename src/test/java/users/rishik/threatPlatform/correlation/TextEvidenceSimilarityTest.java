package users.rishik.threatPlatform.correlation;

import org.junit.jupiter.api.Test;
import users.rishik.threatPlatform.attack.analysis.correlation.TextEvidenceSimilarity;

import static org.junit.jupiter.api.Assertions.assertEquals;

class TextEvidenceSimilarityTest {

    private final TextEvidenceSimilarity similarity =
            new TextEvidenceSimilarity();

    @Test
    void identicalTextShouldHaveFullSimilarity() {

        assertEquals(
                1.0,
                similarity.lcsSimilarity(
                        "wget http://example.com/a",
                        "wget http://example.com/a"
                )
        );
    }

    @Test
    void similarCommandsShouldHavePartialSimilarity() {

        double result = similarity.lcsSimilarity(
                "wget http://example.com/a",
                "wget http://example.com/b"
        );

        assertEquals(
                0.96,
                result,
                0.001
        );
    }

    @Test
    void completelyDifferentTextShouldHaveLowSimilarity() {

        double result = similarity.lcsSimilarity(
                "wget http://example.com/a",
                "whoami"
        );

        assertEquals(
                0.16,
                result,
                0.001
        );
    }
}