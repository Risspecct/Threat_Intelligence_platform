package users.rishik.threatPlatform.attack.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

@Service
@RequiredArgsConstructor
public class SessionFileReader {

    private static final int BATCH_SIZE = 500;
    int batchNumber =  0;

    private final SessionIngestionService ingestionService;

    public int ingestFile(Path filePath) throws IOException {

        int processed = 0;
        List<String> batch = new ArrayList<>(BATCH_SIZE);

        try (Stream<String> lines = Files.lines(filePath)) {

            for (String line : (Iterable<String>) lines::iterator) {

                if (line.isBlank()) {
                    continue;
                }

                batch.add(line);
                processed++;

                if (batch.size() == BATCH_SIZE) {
                    ingestionService.ingestBatchBulk(batch);
                    batchNumber++;
                    System.out.println(
                            "Batch imported: " + batchNumber +
                                    " | Records processed: " + processed
                    );
                    batch.clear();
                }
            }
        }

        // Process remaining records
        if (!batch.isEmpty()) {
            ingestionService.ingestBatchBulk(batch);
            batchNumber++;
            System.out.println(
                    "Batch imported: " + batchNumber + " | Records processed: " + processed
            );
        }

        return processed;
    }
}