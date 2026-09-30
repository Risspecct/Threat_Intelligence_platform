package users.rishik.threatPlatform.attack.analysis.similarity;

import users.rishik.threatPlatform.attack.candidate.CandidatePairGenerationResult;
import users.rishik.threatPlatform.attack.candidate.CandidatePairGenerator;
import users.rishik.threatPlatform.attack.dto.SessionBehavior;
import users.rishik.threatPlatform.attack.service.RawCowrieEventReader;
import users.rishik.threatPlatform.attack.service.SessionBehaviorExtractor;
import users.rishik.threatPlatform.attack.service.SessionEventProcessor;
import users.rishik.threatPlatform.similarity.model.SimilarityResult;
import users.rishik.threatPlatform.similarity.service.SessionSimilarityService;
import users.rishik.threatPlatform.attack.candidate.CandidatePair;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class CandidateSimilarityAnalyzer {

    private final RawCowrieEventReader reader;
    private final SessionBehaviorExtractor extractor;
    private final CandidatePairGenerator candidatePairGenerator;
    private final SessionSimilarityService similarityService;

    public CandidateSimilarityAnalyzer(
            RawCowrieEventReader reader,
            SessionBehaviorExtractor extractor,
            CandidatePairGenerator candidatePairGenerator,
            SessionSimilarityService similarityService
    ) {
        this.reader = reader;
        this.extractor = extractor;
        this.candidatePairGenerator = candidatePairGenerator;
        this.similarityService = similarityService;
    }

    public CandidateSimilarityReport analyze(Path file)
            throws IOException {

        List<SessionBehavior> sessions =
                new ArrayList<>();

        SessionEventProcessor processor =
                new SessionEventProcessor(extractor);

        reader.read(
                file,
                event -> processor.accept(
                        event,
                        sessions::add
                )
        );

        processor.finishRemaining(sessions::add);

        return analyzeSessions(sessions);
    }

    private CandidateSimilarityReport analyzeSessions(
            List<SessionBehavior> sessions
    ) {

        CandidatePairGenerationResult candidateResult =
                candidatePairGenerator.generate(sessions);

        var candidatePairs =
                candidateResult.pairSignals();

        long exactCommandMatches = 0;
        long exactEventMatches = 0;
        long exactFileHashMatches = 0;
        long exactHasshMatches = 0;
        long exactClientVersionMatches = 0;
        long exactDownloadUrlMatches = 0;
        long exactDestinationIpMatches = 0;
        long exactDestinationPortMatches = 0;

        long multipleCoreBehavioralMatches = 0;

        long minimumTemporalDistanceSeconds =
                Long.MAX_VALUE;

        long maximumTemporalDistanceSeconds = 0;

        List<SimilarityResult> similarities = new ArrayList<>(candidatePairs.size());

        for (CandidatePair pair :
                candidatePairs.keySet()) {

            SessionBehavior first =
                    sessions.get(pair.first());

            SessionBehavior second =
                    sessions.get(pair.second());

            SimilarityResult result =
                    similarityService.compare(
                            first,
                            second
                    );

            similarities.add(result);

            if (hasExactNonEmptySequence(
                    first.commandSequence(),
                    second.commandSequence(),
                    result.getCommandSimilarity().similarity()
            )) {
                exactCommandMatches++;
            }

            if (hasExactNonEmptySequence(
                    first.eventSequence(),
                    second.eventSequence(),
                    result.getEventSimilarity().similarity()
            )) {
                exactEventMatches++;
            }

            if (hasExactNonEmptySet(
                    first.fileHashes(),
                    second.fileHashes(),
                    result.getFileHashSimilarity().similarity()
            )) {
                exactFileHashMatches++;
            }

            if (hasExactString(
                    first.hassh(),
                    second.hassh(),
                    result.getHasshSimilarity().similarity()
            )) {
                exactHasshMatches++;
            }

            if (hasExactString(
                    first.clientVersion(),
                    second.clientVersion(),
                    result.getClientVersionSimilarity().similarity()
            )) {
                exactClientVersionMatches++;
            }

            if (hasExactNonEmptySet(
                    first.downloadUrls(),
                    second.downloadUrls(),
                    result.getDownloadUrlSimilarity().similarity()
            )) {
                exactDownloadUrlMatches++;
            }

            if (hasExactNonEmptySet(
                    first.destinationIps(),
                    second.destinationIps(),
                    result.getDestinationIpSimilarity().similarity()
            )) {
                exactDestinationIpMatches++;
            }

            if (hasExactNonEmptySet(
                    toStringList(first.destinationPorts()),
                    toStringList(second.destinationPorts()),
                    result.getDestinationPortSimilarity().similarity()
            )) {
                exactDestinationPortMatches++;
            }

            int coreMatches = 0;

            if (hasExactNonEmptySequence(
                    first.commandSequence(),
                    second.commandSequence(),
                    result.getCommandSimilarity().similarity()
            )) {
                coreMatches++;
            }

            if (hasExactNonEmptySequence(
                    first.eventSequence(),
                    second.eventSequence(),
                    result.getEventSimilarity().similarity()
            )) {
                coreMatches++;
            }

            if (hasExactNonEmptySet(
                    first.fileHashes(),
                    second.fileHashes(),
                    result.getFileHashSimilarity().similarity()
            )) {
                coreMatches++;
            }

            if (coreMatches >= 2) {
                multipleCoreBehavioralMatches++;
            }

            long temporalDistance =
                    result.getTemporalDistanceSeconds();

            minimumTemporalDistanceSeconds =
                    Math.min(
                            minimumTemporalDistanceSeconds,
                            temporalDistance
                    );

            maximumTemporalDistanceSeconds =
                    Math.max(
                            maximumTemporalDistanceSeconds,
                            temporalDistance
                    );
        }

        if (candidatePairs.isEmpty()) {
            minimumTemporalDistanceSeconds = 0;
        }

        return new CandidateSimilarityReport(
                sessions.size(),
                candidatePairs.size(),

                exactCommandMatches,
                exactEventMatches,
                exactFileHashMatches,
                exactHasshMatches,
                exactClientVersionMatches,
                exactDownloadUrlMatches,
                exactDestinationIpMatches,
                exactDestinationPortMatches,

                multipleCoreBehavioralMatches,

                minimumTemporalDistanceSeconds,
                maximumTemporalDistanceSeconds,

                similarities
        );
    }

    private boolean hasExactNonEmptySequence(
            List<String> first,
            List<String> second,
            double similarity
    ) {

        return !first.isEmpty()
                && !second.isEmpty()
                && similarity == 1.0;
    }

    private boolean hasExactNonEmptySet(
            Iterable<String> first,
            Iterable<String> second,
            double similarity
    ) {

        return first.iterator().hasNext()
                && second.iterator().hasNext()
                && similarity == 1.0;
    }

    private boolean hasExactString(
            String first,
            String second,
            double similarity
    ) {

        return first != null
                && !first.isBlank()
                && second != null
                && !second.isBlank()
                && similarity == 1.0;
    }

    private List<String> toStringList(
            List<Integer> values
    ) {

        return values.stream()
                .filter(Objects::nonNull)
                .map(String::valueOf)
                .toList();
    }
}