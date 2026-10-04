package users.rishik.threatPlatform.attack;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import users.rishik.threatPlatform.attack.dto.SourceType;
import users.rishik.threatPlatform.attack.dto.ThreatObservation;
import users.rishik.threatPlatform.attack.mapper.SentryPeerObservationMapper;
import users.rishik.threatPlatform.attack.service.JsonLineReader;
import users.rishik.threatPlatform.attack.service.SentryPeerObservationProcessor;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@Disabled("Manual test - requires local CloudHoneyNet dataset")
class SentryPeerObservationRealDataTest {

    @Test
    void shouldConvertRealSentryPeerEventsToObservations() throws Exception {

        String datasetPath = System.getProperty("sentrypeer.dataset");

        assertNotNull(
                datasetPath,
                "Provide -Dsentrypeer.dataset=<path>"
        );

        SentryPeerObservationProcessor processor =
                new SentryPeerObservationProcessor(
                        new JsonLineReader(new ObjectMapper()),
                        new SentryPeerObservationMapper()
                );

        List<ThreatObservation> observations = new ArrayList<>();

        processor.process(
                Path.of(datasetPath),
                observations::add
        );

        assertFalse(observations.isEmpty());

        ThreatObservation first = observations.get(0);

        assertEquals(
                SourceType.SENTRY_PEER,
                first.getSourceType()
        );

        assertNotNull(first.getTimestamp());
        assertNotNull(first.getSourceIp());
        assertNotNull(first.getDestinationIp());
        assertNotNull(first.getObservationId());
    }
}