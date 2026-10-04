package users.rishik.threatPlatform.attack;

import org.junit.jupiter.api.Test;
import users.rishik.threatPlatform.attack.dto.RawSentryPeerEvent;
import users.rishik.threatPlatform.attack.dto.SourceType;
import users.rishik.threatPlatform.attack.dto.ThreatObservation;
import users.rishik.threatPlatform.attack.mapper.SentryPeerObservationMapper;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class SentryPeerObservationMapperTest {

    @Test
    void shouldMapSentryPeerEventToThreatObservation() {

        RawSentryPeerEvent event = new RawSentryPeerEvent(
                "2025-06-27T10:15:30Z",
                "10.0.0.5",
                5060,
                "10.0.0.10",
                5060,
                "SentryPeer",
                "UDP",
                "INVITE",
                "Example-SIP-Client",
                "1001",
                "event-123"
        );

        SentryPeerObservationMapper mapper =
                new SentryPeerObservationMapper();

        ThreatObservation observation = mapper.map(event);

        assertEquals("event-123", observation.getObservationId());
        assertEquals(SourceType.SENTRY_PEER, observation.getSourceType());
        assertEquals(
                Instant.parse("2025-06-27T10:15:30Z"),
                observation.getTimestamp()
        );

        assertEquals("10.0.0.5", observation.getSourceIp());
        assertEquals(5060, observation.getSourcePort());

        assertEquals("10.0.0.10", observation.getDestinationIp());
        assertEquals(5060, observation.getDestinationPort());

        assertEquals("UDP", observation.getProtocol());
        assertEquals("SentryPeer", observation.getActivityType());

        assertEquals("INVITE", observation.getSipMethod());
        assertEquals(
                "Example-SIP-Client",
                observation.getSipUserAgent()
        );
        assertEquals("1001", observation.getCalledNumber());

        assertNull(observation.getSessionId());
        assertNull(observation.getCommand());
        assertNull(observation.getService());
    }
}