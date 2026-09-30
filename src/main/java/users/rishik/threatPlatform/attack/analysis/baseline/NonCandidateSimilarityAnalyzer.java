package users.rishik.threatPlatform.attack.analysis.baseline;

import users.rishik.threatPlatform.attack.candidate.CandidatePair;
import users.rishik.threatPlatform.attack.candidate.CandidatePairGenerationResult;
import users.rishik.threatPlatform.attack.candidate.CandidatePairGenerator;
import users.rishik.threatPlatform.attack.candidate.NonCandidatePairSampler;
import users.rishik.threatPlatform.attack.dto.SessionBehavior;
import users.rishik.threatPlatform.attack.service.RawCowrieEventReader;
import users.rishik.threatPlatform.attack.service.SessionBehaviorExtractor;
import users.rishik.threatPlatform.attack.service.SessionEventProcessor;
import users.rishik.threatPlatform.similarity.model.SimilarityResult;
import users.rishik.threatPlatform.similarity.service.SessionSimilarityService;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class NonCandidateSimilarityAnalyzer {

    private final RawCowrieEventReader reader;
    private final SessionBehaviorExtractor extractor;
    private final CandidatePairGenerator candidatePairGenerator;
    private final NonCandidatePairSampler sampler;
    private final SessionSimilarityService similarityService;

    public NonCandidateSimilarityAnalyzer(
            RawCowrieEventReader reader,
            SessionBehaviorExtractor extractor,
            CandidatePairGenerator candidatePairGenerator,
            NonCandidatePairSampler sampler,
            SessionSimilarityService similarityService
    ) {
        this.reader = reader;
        this.extractor = extractor;
        this.candidatePairGenerator = candidatePairGenerator;
        this.sampler = sampler;
        this.similarityService = similarityService;
    }

    public NonCandidateSimilarityReport analyze(
            Path file,
            int sampleSize,
            long seed
    ) throws IOException {

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

        return analyzeSessions(
                sessions,
                sampleSize,
                seed
        );
    }

    private NonCandidateSimilarityReport analyzeSessions(
            List<SessionBehavior> sessions,
            int sampleSize,
            long seed
    ) {

        CandidatePairGenerationResult candidateResult =
                candidatePairGenerator.generate(sessions);

        List<CandidatePair> nonCandidatePairs =
                sampler.sample(
                        sessions.size(),
                        candidateResult.pairSignals().keySet(),
                        sampleSize,
                        seed
                );

        List<SimilarityResult> similarities =
                new ArrayList<>(nonCandidatePairs.size());

        for (CandidatePair pair : nonCandidatePairs) {

            SessionBehavior first =
                    sessions.get(pair.first());

            SessionBehavior second =
                    sessions.get(pair.second());

            similarities.add(
                    similarityService.compare(
                            first,
                            second
                    )
            );
        }

        return new NonCandidateSimilarityReport(
                sessions.size(),
                similarities.size(),
                seed,
                similarities
        );
    }
}