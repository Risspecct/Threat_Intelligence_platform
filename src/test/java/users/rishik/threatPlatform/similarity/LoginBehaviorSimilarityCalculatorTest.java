package users.rishik.threatPlatform.similarity;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest
public class LoginBehaviorSimilarityCalculatorTest {
    @Autowired
    LoginBehaviorSimilarityCalculator calculator;

    @Test
    void identicalLoginBehaviorShouldReturnOne() {
        assertEquals(
                1.0,
                calculator.calculate(3, 2, 3, 2)
        );
    }

    @Test
    void completelyDifferentLoginBehaviorShouldReturnZero() {
        assertEquals(
                0.0,
                calculator.calculate(5, 0, 0, 5)
        );
    }

    @Test
    void partiallyDifferentLoginBehaviorShouldReturnIntermediateValue() {
        assertEquals(
                0.75,
                calculator.calculate(3, 1, 2, 1)
        );
    }

    @Test
    void bothHavingNoLoginAttemptsShouldReturnOne() {
        assertEquals(
                1.0,
                calculator.calculate(0, 0, 0, 0)
        );
    }

    @Test
    void oneEmptyLoginPatternShouldReturnZero() {
        assertEquals(
                0.0,
                calculator.calculate(0, 0, 3, 2)
        );
    }
}
