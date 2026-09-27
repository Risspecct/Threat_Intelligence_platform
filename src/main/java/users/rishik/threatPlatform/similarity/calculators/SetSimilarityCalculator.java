package users.rishik.threatPlatform.similarity.calculators;

import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Set;

@Component
public class SetSimilarityCalculator {

    public double calculate(Set<String> first, Set<String> second) {

        if (first.isEmpty() && second.isEmpty()) {
            return 1.0;
        }

        if (first.isEmpty() || second.isEmpty()) {
            return 0.0;
        }

        Set<String> intersection = new HashSet<>(first);
        intersection.retainAll(second);

        Set<String> union = new HashSet<>(first);
        union.addAll(second);

        return (double) intersection.size() / union.size();
    }
}