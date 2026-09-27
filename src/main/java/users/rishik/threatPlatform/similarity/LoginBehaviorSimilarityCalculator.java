package users.rishik.threatPlatform.similarity;

import org.springframework.stereotype.Component;

@Component
public class LoginBehaviorSimilarityCalculator {

    public double calculate(
            int firstSuccess,
            int firstFailure,
            int secondSuccess,
            int secondFailure
    ) {

        int maxTotal =
                Math.max(firstSuccess, secondSuccess)
                        + Math.max(firstFailure, secondFailure);

        if (maxTotal == 0) {
            return 1.0;
        }

        int difference =
                Math.abs(firstSuccess - secondSuccess)
                        + Math.abs(firstFailure - secondFailure);

        return 1.0 - ((double) difference / maxTotal);
    }
}