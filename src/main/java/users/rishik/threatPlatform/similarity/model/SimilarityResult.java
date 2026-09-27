package users.rishik.threatPlatform.similarity.model;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.List;

@Getter
@AllArgsConstructor
public class SimilarityResult {
    private final double behavioralScore;


    private final double contextScore;

    private final long temporalDistanceSeconds;

    private final List<String> evidence;
}