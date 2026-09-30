package users.rishik.threatPlatform.attack.runner;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;
import users.rishik.threatPlatform.attack.analysis.*;
import users.rishik.threatPlatform.attack.service.RawCowrieEventReader;
import users.rishik.threatPlatform.attack.service.SessionBehaviorExtractor;
import users.rishik.threatPlatform.attack.service.SessionFileReader;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class DatasetImportRunner implements ApplicationRunner {

    private final SessionFileReader sessionFileReader;

    @Override
    public void run(ApplicationArguments args) throws Exception {

        if (args.containsOption("import")) {
            runImport(args);
            return;
        }

        if (args.containsOption("analyze")) {
            runAnalysis(args);
        }

        if (args.containsOption("candidate-analysis")) {
            runCandidateAnalysis(args);
            return;
        }

        if (args.containsOption("candidate-overlap-analysis")) {
            runCandidateOverlapAnalysis(args);
            return;
        }
    }

    private void runImport(ApplicationArguments args) throws Exception {

        Path path = getDatasetPath(args, "Dataset import requires --file=<path>");

        System.out.println();
        System.out.println("========================================");
        System.out.println("       Threat Intelligence Import");
        System.out.println("========================================");
        System.out.println("Input: " + path);

        long start = System.currentTimeMillis();

        int processed = sessionFileReader.ingestFile(path);

        long elapsed = System.currentTimeMillis() - start;

        System.out.println();
        System.out.println("Records processed: " + processed);
        System.out.println("Import completed successfully.");
        System.out.printf("Time: %.2f seconds%n", elapsed / 1000.0);
        System.out.println("========================================");
    }

    private void runAnalysis(ApplicationArguments args) throws Exception {

        Path path = getDatasetPath(
                args,
                "Dataset analysis requires --file=<path>"
        );

        System.out.println();
        System.out.println("========================================");
        System.out.println("   Behavioral Feature Distribution");
        System.out.println("========================================");
        System.out.println("Input: " + path);

        long start = System.currentTimeMillis();

        RawCowrieEventReader reader =
                new RawCowrieEventReader(new ObjectMapper());

        SessionBehaviorExtractor extractor =
                new SessionBehaviorExtractor();

        FeatureDistributionAnalyzer analyzer =
                new FeatureDistributionAnalyzer(
                        reader,
                        extractor
                );

        FeatureDistributionReport report =
                analyzer.analyze(path);

        long elapsed = System.currentTimeMillis() - start;

        printReport(report);

        System.out.printf(
                "Analysis time: %.2f seconds%n",
                elapsed / 1000.0
        );

        System.out.println("========================================");
    }

    private Path getDatasetPath(
            ApplicationArguments args,
            String missingFileMessage
    ) {

        if (!args.containsOption("file")) {
            throw new IllegalArgumentException(missingFileMessage);
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

    private void printReport(
            FeatureDistributionReport report
    ) {

        System.out.println();
        System.out.println("Sessions analyzed: "
                + report.sessionsAnalyzed());

        System.out.println();

        System.out.println("Feature coverage:");
        System.out.println("  Commands: "
                + report.sessionsWithCommands());
        System.out.println("  File hashes: "
                + report.sessionsWithFileHashes());
        System.out.println("  HASSH: "
                + report.sessionsWithHassh());
        System.out.println("  Download URLs: "
                + report.sessionsWithDownloadUrls());
        System.out.println("  Destination IPs: "
                + report.sessionsWithDestinationIps());
        System.out.println("  Destination ports: "
                + report.sessionsWithDestinationPorts());

        System.out.println();

        System.out.println("Unique values:");
        System.out.println("  File hashes: "
                + report.uniqueFileHashes());
        System.out.println("  HASSH: "
                + report.uniqueHasshValues());
        System.out.println("  Download URLs: "
                + report.uniqueDownloadUrls());
        System.out.println("  Destination IPs: "
                + report.uniqueDestinationIps());
        System.out.println("  Destination ports: "
                + report.uniqueDestinationPorts());

        System.out.println();

        System.out.println("Top commands:");
        report.topCommands()
                .forEach((value, count) ->
                        System.out.println(
                                "  " + count + " | " + value
                        )
                );

        System.out.println();

        System.out.println("Top file hashes:");
        report.topFileHashes()
                .forEach((value, count) ->
                        System.out.println(
                                "  " + count + " | " + value
                        )
                );

        System.out.println();

        System.out.println("Top HASSH values:");
        report.topHasshValues()
                .forEach((value, count) ->
                        System.out.println(
                                "  " + count + " | " + value
                        )
                );

        System.out.println();

        System.out.println("Top download URLs:");
        report.topDownloadUrls()
                .forEach((value, count) ->
                        System.out.println(
                                "  " + count + " | " + value
                        )
                );

        System.out.println();

        System.out.println("Top destination IPs:");
        report.topDestinationIps()
                .forEach((value, count) ->
                        System.out.println(
                                "  " + count + " | " + value
                        )
                );

        System.out.println();

        System.out.println("Top destination ports:");
        report.topDestinationPorts()
                .forEach((value, count) ->
                        System.out.println(
                                "  " + count + " | " + value
                        )
                );

        System.out.println();
    }

    private void runCandidateAnalysis(
            ApplicationArguments args
    ) throws Exception {

        Path path = getDatasetPath(
                args,
                "Candidate analysis requires --file=<path>"
        );

        System.out.println();
        System.out.println("========================================");
        System.out.println("       Candidate Generation Analysis");
        System.out.println("========================================");
        System.out.println("Input: " + path);

        CandidateGenerationRules rules =
                CandidateGenerationRules.defaults();

        RawCowrieEventReader reader =
                new RawCowrieEventReader(new ObjectMapper());

        SessionBehaviorExtractor extractor =
                new SessionBehaviorExtractor();

        CandidateGenerationAnalyzer analyzer =
                new CandidateGenerationAnalyzer(
                        reader,
                        extractor,
                        rules
                );

        long start = System.currentTimeMillis();

        CandidateGenerationReport report =
                analyzer.analyze(path);

        long elapsed =
                System.currentTimeMillis() - start;

        System.out.println();
        System.out.println(
                "Sessions analyzed: "
                        + report.sessionsAnalyzed()
        );

        System.out.println();
        System.out.println(
                "Maximum feature frequency: "
                        + rules.maxFeatureFrequency()
        );

        System.out.println();
        System.out.println("Eligible feature values:");

        System.out.println(
                "  File hashes: "
                        + report.eligibleFileHashValues()
        );

        System.out.println(
                "  Download URLs: "
                        + report.eligibleUrlValues()
        );

        System.out.println(
                "  Commands: "
                        + report.eligibleCommandValues()
        );

        System.out.println(
                "  HASSH: "
                        + report.eligibleHasshValues()
        );

        System.out.println();
        System.out.println("Candidate pairs by signal:");

        System.out.println(
                "  File hash: "
                        + report.fileHashCandidatePairs()
        );

        System.out.println(
                "  Download URL: "
                        + report.urlCandidatePairs()
        );

        System.out.println(
                "  Command: "
                        + report.commandCandidatePairs()
        );

        System.out.println(
                "  HASSH: "
                        + report.hasshCandidatePairs()
        );

        System.out.println();
        System.out.println(
                "Total candidate pairs before deduplication: "
                        + report.totalCandidatePairsBeforeDeduplication()
        );

        System.out.println(
                "All possible session pairs: "
                        + report.allPossiblePairs()
        );

        System.out.printf(
                "Theoretical reduction: %.4f%%%n",
                report.candidateReductionPercentage()
        );

        System.out.println();
        System.out.printf(
                "Analysis time: %.2f seconds%n",
                elapsed / 1000.0
        );

        System.out.println("========================================");
    }

    private void runCandidateOverlapAnalysis(
            ApplicationArguments args
    ) throws Exception {

        Path path = getDatasetPath(
                args,
                "Candidate overlap analysis requires --file=<path>"
        );

        System.out.println();
        System.out.println("========================================");
        System.out.println("       Candidate Overlap Analysis");
        System.out.println("========================================");
        System.out.println("Input: " + path);

        CandidateGenerationRules rules =
                CandidateGenerationRules.defaults();

        RawCowrieEventReader reader =
                new RawCowrieEventReader(new ObjectMapper());

        SessionBehaviorExtractor extractor =
                new SessionBehaviorExtractor();

        CandidatePairOverlapAnalyzer analyzer =
                new CandidatePairOverlapAnalyzer(
                        reader,
                        extractor,
                        rules
                );

        long start = System.currentTimeMillis();

        CandidatePairOverlapReport report =
                analyzer.analyze(path);

        long elapsed =
                System.currentTimeMillis() - start;

        System.out.println();
        System.out.println(
                "Sessions analyzed: "
                        + report.sessionsAnalyzed()
        );

        System.out.println();
        System.out.println("Candidate pairs:");

        System.out.println(
                "  Before deduplication: "
                        + report.totalCandidatePairsBeforeDeduplication()
        );

        System.out.println(
                "  After deduplication: "
                        + report.uniqueCandidatePairs()
        );

        System.out.println();
        System.out.println("Evidence count:");

        System.out.println(
                "  1 signal: "
                        + report.singleSignalPairs()
        );

        System.out.println(
                "  2 signals: "
                        + report.twoSignalPairs()
        );

        System.out.println(
                "  3 signals: "
                        + report.threeSignalPairs()
        );

        System.out.println(
                "  4 signals: "
                        + report.fourSignalPairs()
        );

        System.out.println();
        System.out.println("Signal combinations:");

        report.signalCombinationCounts()
                .entrySet()
                .stream()
                .sorted(
                        Map.Entry.<String, Long>
                                        comparingByValue()
                                .reversed()
                )
                .forEach(entry ->
                        System.out.println(
                                "  "
                                        + entry.getKey()
                                        + ": "
                                        + entry.getValue()
                        )
                );

        System.out.println();

        System.out.printf(
                "Analysis time: %.2f seconds%n",
                elapsed / 1000.0
        );

        System.out.println("========================================");
    }
}