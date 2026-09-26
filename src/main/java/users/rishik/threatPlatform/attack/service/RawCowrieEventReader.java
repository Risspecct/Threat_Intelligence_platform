package users.rishik.threatPlatform.attack.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import users.rishik.threatPlatform.attack.dto.RawCowrieEvent;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.function.Consumer;

public class RawCowrieEventReader {

    private final ObjectMapper objectMapper;

    public RawCowrieEventReader(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public void read(Path file, Consumer<RawCowrieEvent> consumer) throws IOException {

        try (BufferedReader reader = Files.newBufferedReader(file)) {

            String line;

            while ((line = reader.readLine()) != null) {

                if (line.isBlank()) {
                    continue;
                }

                RawCowrieEvent event = objectMapper.readValue(line, RawCowrieEvent.class);

                consumer.accept(event);
            }
        }
    }
}