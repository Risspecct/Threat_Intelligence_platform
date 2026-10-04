package users.rishik.threatPlatform.attack;

import org.junit.jupiter.api.Test;
import users.rishik.threatPlatform.attack.dto.RawDionaeaEvent;
import users.rishik.threatPlatform.attack.dto.SourceType;
import users.rishik.threatPlatform.attack.dto.ThreatObservation;
import users.rishik.threatPlatform.attack.mapper.DionaeaObservationMapper;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class DionaeaObservationMapperTest {

    @Test
    void shouldMapDionaeaEventToThreatObservation() {

        RawDionaeaEvent event = new RawDionaeaEvent(
                "2025-06-11T15:40:46.327774",
                "2025-06-11T15:40:46.327Z",
                "192.168.1.10",
                51150,
                "10.0.0.1",
                81,
                "Dionaea",
                "user",
                "password",
                new RawDionaeaEvent.Connection(
                        "httpd",
                        "tcp",
                        "accept"
                )
        );

        DionaeaObservationMapper mapper =
                new DionaeaObservationMapper();

        ThreatObservation observation =
                mapper.map(event);

        assertEquals(
                SourceType.DIONAEA,
                observation.getSourceType()
        );

        assertEquals(
                "2025-06-11T15:40:46.327Z",
                observation.getTimestamp().toString()
        );

        assertEquals("192.168.1.10", observation.getSourceIp());
        assertEquals(51150, observation.getSourcePort());

        assertEquals("10.0.0.1", observation.getDestinationIp());
        assertEquals(81, observation.getDestinationPort());

        assertEquals("tcp", observation.getProtocol());
        assertEquals("httpd", observation.getService());

        assertEquals("Dionaea", observation.getActivityType());

        assertEquals("user", observation.getUsername());

        assertNull(observation.getSessionId());
        assertNull(observation.getCommand());
    }
}