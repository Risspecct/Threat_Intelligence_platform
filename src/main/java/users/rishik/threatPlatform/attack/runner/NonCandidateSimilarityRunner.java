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
import users.rishik.threatPlatform.attack.analysis.distribution.FeatureDistribution;
import users.rishik.threatPlatform.attack.analysis.distribution.SimilarityDistributionAnalyzer;
import users.rishik.threatPlatform.attack.analysis.distribution.SimilarityFeature;

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

        SimilarityDistributionAnalyzer distributionAnalyzer =
                new SimilarityDistributionAnalyzer();

        var distributions =
                distributionAnalyzer.analyze(
                        report.similarities()
                );

        printDistributions(distributions);

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

    private void printDistributions(
            java.util.Map<SimilarityFeature, FeatureDistribution> distributions
    ) {

        System.out.println();
        System.out.println(
                "========================================"
        );
        System.out.println(
                "   Non-Candidate Similarity Distributions"
        );
        System.out.println(
                "========================================"
        );

        for (SimilarityFeature feature :
                SimilarityFeature.values()) {

            FeatureDistribution distribution =
                    distributions.get(feature);

            System.out.println();
            System.out.println(feature);

            System.out.printf(
                    "  total count: %d%n",
                    distribution.totalCount()
            );

            System.out.printf(
                    "  comparable count: %d%n",
                    distribution.comparableCount()
            );

            System.out.printf(
                    "  comparable rate: %.6f%n",
                    distribution.comparableRate()
            );

            System.out.printf(
                    "  mean: %.6f%n",
                    distribution.mean()
            );

            System.out.printf(
                    "  p25: %.6f%n",
                    distribution.p25()
            );

            System.out.printf(
                    "  median: %.6f%n",
                    distribution.median()
            );

            System.out.printf(
                    "  p75: %.6f%n",
                    distribution.p75()
            );

            System.out.printf(
                    "  p90: %.6f%n",
                    distribution.p90()
            );

            System.out.printf(
                    "  p95: %.6f%n",
                    distribution.p95()
            );

            System.out.printf(
                    "  p99: %.6f%n",
                    distribution.p99()
            );

            System.out.printf(
                    "  min: %.6f%n",
                    distribution.min()
            );

            System.out.printf(
                    "  max: %.6f%n",
                    distribution.max()
            );
        }
    }
}