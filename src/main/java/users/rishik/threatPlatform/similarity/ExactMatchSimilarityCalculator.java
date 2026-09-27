package users.rishik.threatPlatform.similarity;

import org.springframework.stereotype.Component;

@Component
public class ExactMatchSimilarityCalculator {

    public double calculate(String first, String second) {

        if (first == null || second == null) {
            return 0.0;
        }

        return first.equals(second) ? 1.0 : 0.0;
    }
}