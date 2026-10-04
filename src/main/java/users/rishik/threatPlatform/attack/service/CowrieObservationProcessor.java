package users.rishik.threatPlatform.attack.service;

import users.rishik.threatPlatform.attack.dto.RawCowrieEvent;
import users.rishik.threatPlatform.attack.dto.ThreatObservation;
import users.rishik.threatPlatform.attack.mapper.CowrieObservationMapper;

import java.io.IOException;
import java.nio.file.Path;
import java.util.function.Consumer;

public class CowrieObservationProcessor {

    private final JsonLineReader eventReader;
    private final CowrieObservationMapper mapper;

    public CowrieObservationProcessor(
            JsonLineReader eventReader,
            CowrieObservationMapper mapper) {

        this.eventReader = eventReader;
        this.mapper = mapper;
    }

    public void process(
            Path file,
            Consumer<ThreatObservation> consumer) throws IOException {

        eventReader.read(
                file,
                RawCowrieEvent.class,
                event -> {

                    ThreatObservation observation =
                            mapper.map(event);

                    consumer.accept(observation);
                }
        );
    }
}