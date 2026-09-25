package users.rishik.threatPlatform.attack.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

@Service
@RequiredArgsConstructor
public class SessionFileReader {

    private final SessionIngestionService ingestionService;

    public int ingestFile(Path filePath) throws IOException {

        int processed = 0;

        try (Stream<String> lines = Files.lines(filePath)) {

            for (String line : (Iterable<String>) lines::iterator) {

                if (line.isBlank()) {
                    continue;
                }

                ingestionService.ingest(line);
                processed++;
            }
        }

        return processed;
    }
}