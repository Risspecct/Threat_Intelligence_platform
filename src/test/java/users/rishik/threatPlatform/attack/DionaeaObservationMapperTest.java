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

        RawDionaeaEvent.Connection connection =
                new RawDionaeaEvent.Connection(
                        "httpd",
                        "tcp",
                        "accept"
                );

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
                        "tcp",
                        "tcp",
                        "httpd"
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
                "2025-06-27T10:15:30Z",
                observation.getTimestamp().toString()
        );

        assertEquals("10.0.0.5", observation.getSourceIp());
        assertEquals(54321, observation.getSourcePort());

        assertEquals("10.0.0.10", observation.getDestinationIp());
        assertEquals(80, observation.getDestinationPort());

        assertEquals("tcp", observation.getProtocol());
        assertEquals("httpd", observation.getService());

        assertEquals("Dionaea", observation.getActivityType());

        assertEquals("admin", observation.getUsername());

        assertNull(observation.getSessionId());
        assertNull(observation.getCommand());
    }
}