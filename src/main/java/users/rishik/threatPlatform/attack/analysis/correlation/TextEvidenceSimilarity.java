package users.rishik.threatPlatform.attack.analysis.correlation;

public class TextEvidenceSimilarity {

    public double lcsSimilarity(String first, String second) {

        if (first == null || second == null) {
            return 0.0;
        }

        if (first.equals(second)) {
            return 1.0;
        }

        if (first.isBlank() || second.isBlank()) {
            return 0.0;
        }

        int[][] dp = new int[first.length() + 1][second.length() + 1];

        for (int i = 1; i <= first.length(); i++) {
            for (int j = 1; j <= second.length(); j++) {

                if (first.charAt(i - 1) == second.charAt(j - 1)) {
                    dp[i][j] = dp[i - 1][j - 1] + 1;
                } else {
                    dp[i][j] = Math.max(
                            dp[i - 1][j],
                            dp[i][j - 1]
                    );
                }
            }
        }

        int lcsLength = dp[first.length()][second.length()];

        return (double) lcsLength
                / Math.max(first.length(), second.length());
    }
}