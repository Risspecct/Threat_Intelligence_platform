package users.rishik.threatPlatform.similarity.model;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.List;

@Getter
@AllArgsConstructor
public class SimilarityResult {

    private final double commandSimilarity;

    private final double eventSimilarity;

    private final double fileHashSimilarity;

    private final double hasshSimilarity;

    private final double clientVersionSimilarity;

    private final double downloadUrlSimilarity;

    private final double destinationIpSimilarity;

    private final double destinationPortSimilarity;

    private final double loginBehaviorSimilarity;

    private final long temporalDistanceSeconds;

    private final List<String> evidence;
}