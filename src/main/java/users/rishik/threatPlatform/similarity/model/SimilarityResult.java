package users.rishik.threatPlatform.similarity.model;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.List;

@Getter
@AllArgsConstructor
public class SimilarityResult {

    private final FeatureSimilarity commandSimilarity;

    private final FeatureSimilarity eventSimilarity;

    private final FeatureSimilarity fileHashSimilarity;

    private final FeatureSimilarity hasshSimilarity;

    private final FeatureSimilarity clientVersionSimilarity;

    private final FeatureSimilarity downloadUrlSimilarity;

    private final FeatureSimilarity destinationIpSimilarity;

    private final FeatureSimilarity destinationPortSimilarity;

    private final FeatureSimilarity loginBehaviorSimilarity;

    private final long temporalDistanceSeconds;

    private final List<String> evidence;
}
