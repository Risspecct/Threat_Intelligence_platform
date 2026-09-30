package users.rishik.threatPlatform.attack.runner;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;
import users.rishik.threatPlatform.attack.analysis.baseline.NonCandidateSimilarityAnalyzer;
import users.rishik.threatPlatform.attack.analysis.baseline.NonCandidateSimilarityReport;
import users.rishik.threatPlatform.attack.candidate.CandidateGenerationRules;
import users.rishik.threatPlatform.attack.candidate.CandidatePairGenerator;
import users.rishik.threatPlatform.attack.candidate.NonCandidatePairSampler;
import users.rishik.threatPlatform.attack.service.RawCowrieEventReader;
import users.rishik.threatPlatform.attack.service.SessionBehaviorExtractor;
import users.rishik.threatPlatform.similarity.service.SessionSimilarityService;

import java.nio.file.Files;
import java.nio.file.Path;

@Component
@RequiredArgsConstructor
public class NonCandidateSimilarityRunner
        implements ApplicationRunner {

    private final SessionSimilarityService similarityService;

    @Override
    public void run(ApplicationArguments args)
            throws Exception {

        if (!args.containsOption(
                "non-candidate-similarity-analysis"
        )) {
            return;
        }

        Path path = getDatasetPath(args);

        int sampleSize = 49_717;
        long seed = 42L;

        System.out.println();
        System.out.println(
                "========================================"
        );
        System.out.println(
                "   Non-Candidate Similarity Baseline"
        );
        System.out.println(
                "========================================"
        );
        System.out.println(
                "Input: " + path
        );
        System.out.println(
                "Sample size: " + sampleSize
        );
        System.out.println(
                "Seed: " + seed
        );

        long start = System.currentTimeMillis();

        RawCowrieEventReader reader =
                new RawCowrieEventReader(
                        new ObjectMapper()
                );

        SessionBehaviorExtractor extractor =
                new SessionBehaviorExtractor();

        CandidatePairGenerator candidatePairGenerator =
                new CandidatePairGenerator(
                        CandidateGenerationRules.defaults()
                );

        NonCandidatePairSampler sampler =
                new NonCandidatePairSampler();

        NonCandidateSimilarityAnalyzer analyzer =
                new NonCandidateSimilarityAnalyzer(
                        reader,
                        extractor,
                        candidatePairGenerator,
                        sampler,
                        similarityService
                );

        NonCandidateSimilarityReport report =
                analyzer.analyze(
                        path,
                        sampleSize,
                        seed
                );

        long elapsed =
                System.currentTimeMillis() - start;

        System.out.println();
        System.out.println(
                "Sessions: "
                        + report.sessionCount()
        );

        System.out.println(
                "Non-candidate sample: "
                        + report.sampleSize()
        );

        System.out.println(
                "Seed: "
                        + report.seed()
        );

        System.out.println(
                "Similarity results: "
                        + report.similarities().size()
        );

        System.out.printf(
                "Analysis time: %.2f seconds%n",
                elapsed / 1000.0
        );

        System.out.println(
                "========================================"
        );
    }

    private Path getDatasetPath(
            ApplicationArguments args
    ) {

        if (!args.containsOption("file")) {
            throw new IllegalArgumentException(
                    "Non-candidate similarity analysis " +
                            "requires --file=<path>"
            );
        }

        String filePath =
                args.getOptionValues("file").getFirst();

        Path path = Path.of(filePath);

        if (!Files.isRegularFile(path)) {
            throw new IllegalArgumentException(
                    "Dataset file does not exist: " + path
            );
        }

        return path;
    }
}