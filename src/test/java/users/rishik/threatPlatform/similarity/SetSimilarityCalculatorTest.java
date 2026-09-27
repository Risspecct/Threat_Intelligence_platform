package users.rishik.threatPlatform.similarity;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import users.rishik.threatPlatform.similarity.calculator.SetSimilarityCalculator;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest
public class SetSimilarityCalculatorTest {
    @Autowired
    private SetSimilarityCalculator calculator;

    @Test
    void identicalSetsShouldReturnOne() {
        Set<String> first = Set.of("A", "B", "C");
        Set<String> second = Set.of("A", "B", "C");

        assertEquals(1.0, calculator.calculate(first, second));
    }

    @Test
    void completelyDifferentSetsShouldReturnZero() {
        Set<String> first = Set.of("A", "B");
        Set<String> second = Set.of("C", "D");

        assertEquals(0.0, calculator.calculate(first, second));
    }

    @Test
    void partiallyOverlappingSetsShouldReturnJaccardSimilarity() {
        Set<String> first = Set.of("A", "B", "C");
        Set<String> second = Set.of("B", "C", "D");

        assertEquals(0.5, calculator.calculate(first, second));
    }
}
