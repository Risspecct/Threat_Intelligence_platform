package users.rishik.threatPlatform.attack.candidate;

import java.util.Map;

public class FeatureFrequencyFilter {

    public static <T> Map<T, Long> filter(
            Map<T, Long> frequencies,
            int maxFrequency
    ) {

        return frequencies.entrySet()
                .stream()
                .filter(entry ->
                        entry.getValue() >= 2
                                && entry.getValue() <= maxFrequency
                )
                .collect(
                        java.util.stream.Collectors.toMap(
                                Map.Entry::getKey,
                                Map.Entry::getValue
                        )
                );
    }
}