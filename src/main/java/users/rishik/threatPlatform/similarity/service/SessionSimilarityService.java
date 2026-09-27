package users.rishik.threatPlatform.similarity.service;

import org.springframework.stereotype.Service;
import users.rishik.threatPlatform.attack.dto.SessionBehavior;
import users.rishik.threatPlatform.similarity.calculator.ExactMatchSimilarityCalculator;
import users.rishik.threatPlatform.similarity.calculator.LoginBehaviorSimilarityCalculator;
import users.rishik.threatPlatform.similarity.calculator.SequenceSimilarityCalculator;
import users.rishik.threatPlatform.similarity.calculator.SetSimilarityCalculator;
import users.rishik.threatPlatform.similarity.model.SimilarityResult;

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

        double commandSimilarity =
                sequenceSimilarityCalculator.calculate(
                        first.commandSequence(),
                        second.commandSequence()
                );

        double eventSimilarity =
                sequenceSimilarityCalculator.calculate(
                        first.eventSequence(),
                        second.eventSequence()
                );

        double fileHashSimilarity =
                setSimilarityCalculator.calculate(
                        new HashSet<>(first.fileHashes()),
                        new HashSet<>(second.fileHashes())
                );

        double hasshSimilarity =
                exactMatchSimilarityCalculator.calculate(
                        first.hassh(),
                        second.hassh()
                );

        double clientVersionSimilarity =
                exactMatchSimilarityCalculator.calculate(
                        first.clientVersion(),
                        second.clientVersion()
                );

        double downloadUrlSimilarity =
                setSimilarityCalculator.calculate(
                        new HashSet<>(first.downloadUrls()),
                        new HashSet<>(second.downloadUrls())
                );

        double destinationIpSimilarity =
                setSimilarityCalculator.calculate(
                        new HashSet<>(first.destinationIps()),
                        new HashSet<>(second.destinationIps())
                );

        double destinationPortSimilarity =
                setSimilarityCalculator.calculate(
                        toStringSet(first.destinationPorts()),
                        toStringSet(second.destinationPorts())
                );

        double loginBehaviorSimilarity =
                loginBehaviorSimilarityCalculator.calculate(
                        first.loginSuccess() ? 1 : 0,
                        first.loginFailure() ? 1 : 0,
                        second.loginSuccess() ? 1 : 0,
                        second.loginFailure() ? 1 : 0
                );

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
}