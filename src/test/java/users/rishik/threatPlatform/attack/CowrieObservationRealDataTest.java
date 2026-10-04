package users.rishik.threatPlatform.attack;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import users.rishik.threatPlatform.attack.dto.ThreatObservation;
import users.rishik.threatPlatform.attack.mapper.CowrieObservationMapper;
import users.rishik.threatPlatform.attack.service.CowrieObservationProcessor;
import users.rishik.threatPlatform.attack.service.JsonLineReader;
import users.rishik.threatPlatform.attack.service.RawCowrieEventReader;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;

@Disabled("Manual test - requires local CloudHoneyNet dataset")
class CowrieObservationRealDataTest {

    @Test
    void shouldConvertRealCowrieEventsToObservations()
            throws Exception {

        String datasetPath =
                System.getProperty("cowrie.dataset");

        assertNotNull(
                datasetPath,
                "Provide -Dcowrie.dataset=<path>"
        );

        CowrieObservationProcessor processor =
                new CowrieObservationProcessor(
                        new JsonLineReader(new ObjectMapper()),
                        new CowrieObservationMapper()
                );

        List<ThreatObservation> observations =
                new ArrayList<>();

        processor.process(
                Path.of(datasetPath),
                observations::add
        );

        assertFalse(observations.isEmpty());

        ThreatObservation first =
                observations.get(0);

        assertEquals(
                users.rishik.threatPlatform.attack.dto.SourceType.COWRIE,
                first.getSourceType()
        );

        assertNotNull(first.getTimestamp());
        assertNotNull(first.getSourceIp());
    }
}