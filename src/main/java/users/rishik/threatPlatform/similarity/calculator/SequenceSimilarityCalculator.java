package users.rishik.threatPlatform.similarity.calculator;

import org.springframework.stereotype.Component;
import java.util.List;

@Component
public class SequenceSimilarityCalculator {

    public double calculate(List<String> first, List<String> second) {

        if (first.isEmpty() && second.isEmpty()) {
            return 1.0;
        }

        if (first.isEmpty() || second.isEmpty()) {
            return 0.0;
        }

        int lcsLength = lcsLength(first, second);

        return (double) lcsLength /
                Math.max(first.size(), second.size());
    }

    private int lcsLength(List<String> first, List<String> second) {

        int[][] dp =
                new int[first.size() + 1][second.size() + 1];

        for (int i = 1; i <= first.size(); i++) {

            for (int j = 1; j <= second.size(); j++) {

                if (first.get(i - 1).equals(second.get(j - 1))) {

                    dp[i][j] = dp[i - 1][j - 1] + 1;

                } else {

                    dp[i][j] = Math.max(
                            dp[i - 1][j],
                            dp[i][j - 1]
                    );
                }
            }
        }

        return dp[first.size()][second.size()];
    }
}