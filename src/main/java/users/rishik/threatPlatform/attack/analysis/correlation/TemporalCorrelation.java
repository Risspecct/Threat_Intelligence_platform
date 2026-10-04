package users.rishik.threatPlatform.attack.analysis.correlation;

import java.time.Duration;
import java.time.Instant;

public record TemporalCorrelation(
        Duration distance
) {

    public static TemporalCorrelation between(
            Instant first,
            Instant second) {

        if (first == null || second == null) {
            return new TemporalCorrelation(null);
        }

        return new TemporalCorrelation(
                Duration.between(first, second).abs()
        );
    }
}