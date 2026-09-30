package users.rishik.threatPlatform.attack.candidate;

import users.rishik.threatPlatform.attack.dto.SessionBehavior;

import java.util.*;
import java.util.function.Function;

public class CandidatePairGenerator {

    private final CandidateGenerationRules rules;

    public CandidatePairGenerator(CandidateGenerationRules rules) {
        this.rules = rules;
    }

    public CandidatePairGenerationResult generate(
            List<SessionBehavior> sessions
    ) {

        Map<CandidatePair, EnumSet<CandidateSignal>> pairSignals =
                new HashMap<>();

        long totalPairsBeforeDeduplication = 0;

        totalPairsBeforeDeduplication += addSignalPairs(
                sessions,
                SessionBehavior::fileHashes,
                CandidateSignal.FILE_HASH,
                pairSignals
        );

        totalPairsBeforeDeduplication += addSignalPairs(
                sessions,
                SessionBehavior::downloadUrls,
                CandidateSignal.DOWNLOAD_URL,
                pairSignals
        );

        totalPairsBeforeDeduplication += addSignalPairs(
                sessions,
                SessionBehavior::commandSequence,
                CandidateSignal.COMMAND,
                pairSignals
        );

        totalPairsBeforeDeduplication += addSignalPairs(
                sessions,
                session -> session.hassh() == null
                        ? Set.of()
                        : Set.of(session.hassh()),
                CandidateSignal.HASSH,
                pairSignals
        );

        return new CandidatePairGenerationResult(
                pairSignals,
                totalPairsBeforeDeduplication
        );
    }

    private <T> long addSignalPairs(
            List<SessionBehavior> sessions,
            Function<SessionBehavior, Collection<T>> featureExtractor,
            CandidateSignal signal,
            Map<CandidatePair, EnumSet<CandidateSignal>> pairSignals
    ) {

        Map<T, List<Integer>> sessionsByFeature =
                new HashMap<>();

        for (int i = 0; i < sessions.size(); i++) {

            Collection<T> features =
                    featureExtractor.apply(sessions.get(i));

            if (features == null) {
                continue;
            }

            Set<T> distinctFeatures =
                    new HashSet<>(features);

            for (T feature : distinctFeatures) {

                if (feature == null) {
                    continue;
                }

                sessionsByFeature
                        .computeIfAbsent(
                                feature,
                                ignored -> new ArrayList<>()
                        )
                        .add(i);
            }
        }

        long pairCount = 0;

        for (List<Integer> sessionIndexes :
                sessionsByFeature.values()) {

            if (sessionIndexes.size() < 2) {
                continue;
            }

            if (sessionIndexes.size()
                    > rules.maxFeatureFrequency()) {
                continue;
            }

            pairCount +=
                    (long) sessionIndexes.size()
                            * (sessionIndexes.size() - 1)
                            / 2;

            for (int i = 0;
                 i < sessionIndexes.size();
                 i++) {

                for (int j = i + 1;
                     j < sessionIndexes.size();
                     j++) {

                    CandidatePair pair =
                            new CandidatePair(
                                    sessionIndexes.get(i),
                                    sessionIndexes.get(j)
                            );

                    pairSignals
                            .computeIfAbsent(
                                    pair,
                                    ignored ->
                                            EnumSet.noneOf(
                                                    CandidateSignal.class
                                            )
                            )
                            .add(signal);
                }
            }
        }

        return pairCount;
    }
}