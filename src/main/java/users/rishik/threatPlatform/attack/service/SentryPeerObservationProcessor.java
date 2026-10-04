package users.rishik.threatPlatform.attack.service;

import users.rishik.threatPlatform.attack.dto.RawSentryPeerDocument;
import users.rishik.threatPlatform.attack.dto.ThreatObservation;
import users.rishik.threatPlatform.attack.mapper.SentryPeerObservationMapper;

import java.io.IOException;
import java.nio.file.Path;
import java.util.function.Consumer;

public class SentryPeerObservationProcessor {

    private final JsonLineReader eventReader;
    private final SentryPeerObservationMapper mapper;

    public SentryPeerObservationProcessor(
            JsonLineReader eventReader,
            SentryPeerObservationMapper mapper
    ) {
        this.eventReader = eventReader;
        this.mapper = mapper;
    }

    public void process(
            Path file,
            Consumer<ThreatObservation> consumer
    ) throws IOException {

        eventReader.read(
                file,
                RawSentryPeerDocument.class,
                document -> {
                    ThreatObservation observation = mapper.map(document._source());
                    consumer.accept(observation);
                }
        );
    }
}