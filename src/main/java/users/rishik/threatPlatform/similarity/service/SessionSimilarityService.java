package users.rishik.threatPlatform.similarity.service;

import org.springframework.stereotype.Service;
import users.rishik.threatPlatform.attack.dto.SessionBehavior;
import users.rishik.threatPlatform.similarity.calculator.ExactMatchSimilarityCalculator;
import users.rishik.threatPlatform.similarity.calculator.LoginBehaviorSimilarityCalculator;
import users.rishik.threatPlatform.similarity.calculator.SequenceSimilarityCalculator;
import users.rishik.threatPlatform.similarity.calculator.SetSimilarityCalculator;
import users.rishik.threatPlatform.similarity.model.SimilarityResult;
import users.rishik.threatPlatform.similarity.model.FeatureSimilarity;

import java.time.Duration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
public class SessionSimilarityService {

    private final SequenceSimilarityCalculator sequenceSimilarityCalculator;
    private final SetSimilarityCalculator setSimilarityCalculator;
    private final ExactMatchSimilarityCalculator exactMatchSimilarityCalculator;
    private final LoginBehaviorSimilarityCalculator loginBehaviorSimilarityCalculator;

    public SessionSimilarityService(
            SequenceSimilarityCalculator sequenceSimilarityCalculator,
            SetSimilarityCalculator setSimilarityCalculator,
            ExactMatchSimilarityCalculator exactMatchSimilarityCalculator,
            LoginBehaviorSimilarityCalculator loginBehaviorSimilarityCalculator
    ) {
        this.sequenceSimilarityCalculator = sequenceSimilarityCalculator;
        this.setSimilarityCalculator = setSimilarityCalculator;
        this.exactMatchSimilarityCalculator = exactMatchSimilarityCalculator;
        this.loginBehaviorSimilarityCalculator = loginBehaviorSimilarityCalculator;
    }

    public SimilarityResult compare(
            SessionBehavior first,
            SessionBehavior second
    ) {

        FeatureSimilarity commandSimilarity = sequenceSimilarity(
                first.commandSequence(), second.commandSequence());

        FeatureSimilarity eventSimilarity = sequenceSimilarity(
                first.eventSequence(), second.eventSequence());

        FeatureSimilarity fileHashSimilarity = setSimilarity(
                new HashSet<>(first.fileHashes()), new HashSet<>(second.fileHashes()));

        FeatureSimilarity hasshSimilarity = exactSimilarity(first.hassh(), second.hassh());

        FeatureSimilarity clientVersionSimilarity = exactSimilarity(
                first.clientVersion(), second.clientVersion());

        FeatureSimilarity downloadUrlSimilarity = setSimilarity(
                new HashSet<>(first.downloadUrls()), new HashSet<>(second.downloadUrls()));

        FeatureSimilarity destinationIpSimilarity = setSimilarity(
                new HashSet<>(first.destinationIps()), new HashSet<>(second.destinationIps()));

        FeatureSimilarity destinationPortSimilarity = setSimilarity(
                toStringSet(first.destinationPorts()), toStringSet(second.destinationPorts()));

        FeatureSimilarity loginBehaviorSimilarity = loginBehaviorSimilarity(first, second);

        long temporalDistanceSeconds =
                Duration.between(
                        first.firstSeen(),
                        second.firstSeen()
                ).abs().getSeconds();

        List<String> evidence = List.of();

        return new SimilarityResult(
                commandSimilarity,
                eventSimilarity,
                fileHashSimilarity,
                hasshSimilarity,
                clientVersionSimilarity,
                downloadUrlSimilarity,
                destinationIpSimilarity,
                destinationPortSimilarity,
                loginBehaviorSimilarity,
                temporalDistanceSeconds,
                evidence
        );
    }

    private Set<String> toStringSet(List<Integer> ports) {

        Set<String> result = new HashSet<>();

        for (Integer port : ports) {
            result.add(String.valueOf(port));
        }

        return result;
    }

    private FeatureSimilarity sequenceSimilarity(List<String> first, List<String> second) {
        return new FeatureSimilarity(sequenceSimilarityCalculator.calculate(first, second),
                !first.isEmpty() && !second.isEmpty());
    }

    private FeatureSimilarity setSimilarity(Set<String> first, Set<String> second) {
        return new FeatureSimilarity(setSimilarityCalculator.calculate(first, second),
                !first.isEmpty() && !second.isEmpty());
    }

    private FeatureSimilarity exactSimilarity(String first, String second) {
        boolean firstPresent = first != null && !first.isBlank();
        boolean secondPresent = second != null && !second.isBlank();
        if (!firstPresent && !secondPresent) {
            return new FeatureSimilarity(1.0, false);
        }
        if (!firstPresent || !secondPresent) {
            return new FeatureSimilarity(0.0, false);
        }
        return new FeatureSimilarity(exactMatchSimilarityCalculator.calculate(first, second), true);
    }

    private FeatureSimilarity loginBehaviorSimilarity(
            SessionBehavior first,
            SessionBehavior second
    ) {
        int firstSuccess = first.loginSuccess() ? 1 : 0;
        int firstFailure = first.loginFailure() ? 1 : 0;
        int secondSuccess = second.loginSuccess() ? 1 : 0;
        int secondFailure = second.loginFailure() ? 1 : 0;
        return new FeatureSimilarity(loginBehaviorSimilarityCalculator.calculate(
                firstSuccess, firstFailure, secondSuccess, secondFailure),
                firstSuccess + firstFailure > 0 && secondSuccess + secondFailure > 0);
    }
}
