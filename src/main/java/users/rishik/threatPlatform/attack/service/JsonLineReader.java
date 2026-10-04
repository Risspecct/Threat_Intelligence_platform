package users.rishik.threatPlatform.attack.service;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.function.Consumer;

public class JsonLineReader {

    private final ObjectMapper objectMapper;

    public JsonLineReader(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public <T> void read(
            Path file,
            Class<T> type,
            Consumer<T> consumer) throws IOException {

        try (BufferedReader reader =
                     Files.newBufferedReader(file)) {

            String line;

            while ((line = reader.readLine()) != null) {

                if (line.isBlank()) {
                    continue;
                }

                T event =
                        objectMapper.readValue(line, type);

                consumer.accept(event);
            }
        }
    }
}