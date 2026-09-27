package users.rishik.threatPlatform.attack.runner;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;
import users.rishik.threatPlatform.attack.service.SessionFileReader;

import java.nio.file.Files;
import java.nio.file.Path;

@Component
@RequiredArgsConstructor
public class DatasetImportRunner implements ApplicationRunner {

    private final SessionFileReader sessionFileReader;

    @Override
    public void run(ApplicationArguments args) throws Exception {

        if (!args.containsOption("import")) {
            return;
        }

        if (!args.containsOption("file")) {
            throw new IllegalArgumentException(
                    "Dataset import requires --file=<path>"
            );
        }

        String filePath = args.getOptionValues("file").getFirst();
        Path path = Path.of(filePath);

        if (!Files.isRegularFile(path)) {
            throw new IllegalArgumentException(
                    "Dataset file does not exist: " + path
            );
        }

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
}