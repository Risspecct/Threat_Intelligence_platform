package users.rishik.threatPlatform.attack;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import users.rishik.threatPlatform.attack.dto.SourceType;
import users.rishik.threatPlatform.attack.dto.ThreatObservation;
import users.rishik.threatPlatform.attack.mapper.DionaeaObservationMapper;
import users.rishik.threatPlatform.attack.service.DionaeaObservationProcessor;
import users.rishik.threatPlatform.attack.service.JsonLineReader;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@Disabled("Manual test - requires local CloudHoneyNet dataset")
class DionaeaObservationRealDataTest {

    @Test
    void shouldConvertRealDionaeaEventsToObservations()
            throws Exception {

        String datasetPath =
                System.getProperty("dionaea.dataset");

        assertNotNull(
                datasetPath,
                "Provide -Ddionaea.dataset=<path>"
        );

        DionaeaObservationProcessor processor =
                new DionaeaObservationProcessor(
                        new JsonLineReader(new ObjectMapper()),
                        new DionaeaObservationMapper()
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
                SourceType.DIONAEA,
                first.getSourceType()
        );

        assertNotNull(first.getTimestamp());
        assertNotNull(first.getSourceIp());
    }
}