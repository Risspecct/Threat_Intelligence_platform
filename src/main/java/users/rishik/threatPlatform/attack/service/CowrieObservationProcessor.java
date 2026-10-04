package users.rishik.threatPlatform.attack.service;

import users.rishik.threatPlatform.attack.dto.ThreatObservation;
import users.rishik.threatPlatform.attack.mapper.CowrieObservationMapper;

import java.io.IOException;
import java.nio.file.Path;
import java.util.function.Consumer;

public class CowrieObservationProcessor {

    private final RawCowrieEventReader eventReader;
    private final CowrieObservationMapper mapper;

    public CowrieObservationProcessor(
            RawCowrieEventReader eventReader,
            CowrieObservationMapper mapper) {

        this.eventReader = eventReader;
        this.mapper = mapper;
    }

    public void process(
            Path file,
            Consumer<ThreatObservation> consumer) throws IOException {

        eventReader.read(
                file,
                event -> {
                    ThreatObservation observation =
                            mapper.map(event);

                    consumer.accept(observation);
                }
        );
    }
}