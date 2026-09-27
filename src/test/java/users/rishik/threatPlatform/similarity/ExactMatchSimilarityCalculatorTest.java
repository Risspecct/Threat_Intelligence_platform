package users.rishik.threatPlatform.similarity;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import users.rishik.threatPlatform.similarity.calculator.ExactMatchSimilarityCalculator;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest
public class ExactMatchSimilarityCalculatorTest {
    @Autowired
    private ExactMatchSimilarityCalculator calculator;

    @Test
    void identicalValuesShouldReturnOne() {
        assertEquals(
                1.0,
                calculator.calculate("abc123", "abc123")
        );
    }

    @Test
    void differentValuesShouldReturnZero() {
        assertEquals(
                0.0,
                calculator.calculate("abc123", "xyz789")
        );
    }

    @Test
    void nullValuesShouldReturnZero() {
        assertEquals(
                0.0,
                calculator.calculate(null, "abc123")
        );

        assertEquals(
                0.0,
                calculator.calculate("abc123", null)
        );

        assertEquals(
                0.0,
                calculator.calculate(null, null)
        );
    }
}
