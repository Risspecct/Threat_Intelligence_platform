package users.rishik.threatPlatform.attack.service;

import users.rishik.threatPlatform.attack.dto.RawDionaeaDocument;
import users.rishik.threatPlatform.attack.dto.RawDionaeaEvent;
import users.rishik.threatPlatform.attack.dto.ThreatObservation;
import users.rishik.threatPlatform.attack.mapper.DionaeaObservationMapper;

import java.io.IOException;
import java.nio.file.Path;
import java.util.function.Consumer;
public class DionaeaObservationProcessor {


    private final JsonLineReader eventReader;
    private final DionaeaObservationMapper mapper;

    public DionaeaObservationProcessor(
            JsonLineReader eventReader,
            DionaeaObservationMapper mapper) {

        this.eventReader = eventReader;
        this.mapper = mapper;
    }

    public void process(
            Path file,
            Consumer<ThreatObservation> consumer) throws IOException {

        eventReader.read(
                file,
                RawDionaeaDocument.class,
                document -> {

                    ThreatObservation observation =
                            mapper.map(document._source());

                    consumer.accept(observation);
                }
        );
    }
}