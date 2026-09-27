package users.rishik.threatPlatform.similarity;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest
public class SequenceSimilarityCalculatorTest {
    @Autowired
    private SequenceSimilarityCalculator calculator;

    @Test
    void shouldCalculatePartialSequenceSimilarity() {

        List<String> first =
                List.of("login", "command", "download", "execute");

        List<String> second =
                List.of("login", "command", "execute");

        assertEquals(
                0.75,
                calculator.calculate(first, second)
        );
    }
}
