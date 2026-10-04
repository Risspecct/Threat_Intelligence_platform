package users.rishik.threatPlatform.attack;

import org.junit.jupiter.api.Test;
import users.rishik.threatPlatform.attack.dto.RawCowrieEvent;
import users.rishik.threatPlatform.attack.dto.RawDionaeaEvent;
import users.rishik.threatPlatform.attack.dto.RawSentryPeerEvent;
import users.rishik.threatPlatform.attack.dto.SourceType;
import users.rishik.threatPlatform.attack.dto.ThreatObservation;
import users.rishik.threatPlatform.attack.mapper.CowrieObservationMapper;
import users.rishik.threatPlatform.attack.mapper.DionaeaObservationMapper;
import users.rishik.threatPlatform.attack.mapper.SentryPeerObservationMapper;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ThreatObservationNormalizationTest {

    @Test
    void shouldNormalizeCommonNetworkFieldsAcrossSources() {

        RawCowrieEvent cowrieEvent = new RawCowrieEvent(
                "2025-06-27T10:15:30Z",
                54321,
                "10.0.0.10",
                22,
                "cowrie.login.success",
                "session-1",
                "sensor-1",
                1,
                "root",
                "password",
                null,
                null,
                null,
                "ssh",
                "hassh-123",
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                "1.0",
                "10.0.0.5",
                "10.0.0.10"
        );

        RawDionaeaEvent dionaeaEvent = new RawDionaeaEvent(
                "2025-06-27T10:15:30Z",
                "10.0.0.5",
                54321,
                "10.0.0.10",
                80,
                "Dionaea",
                "admin",
                "password",
                new RawDionaeaEvent.Connection(
                        "httpd",
                        "tcp",
                        "accept"
                )
        );

        RawSentryPeerEvent sentryPeerEvent = new RawSentryPeerEvent(
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

        ThreatObservation cowrie =
                new CowrieObservationMapper().map(cowrieEvent);

        ThreatObservation dionaea =
                new DionaeaObservationMapper().map(dionaeaEvent);

        ThreatObservation sentryPeer =
                new SentryPeerObservationMapper().map(sentryPeerEvent);

        assertEquals(SourceType.COWRIE, cowrie.getSourceType());
        assertEquals("10.0.0.5", cowrie.getSourceIp());
        assertEquals(54321, cowrie.getSourcePort());
        assertEquals("10.0.0.10", cowrie.getDestinationIp());
        assertEquals(22, cowrie.getDestinationPort());

        assertEquals(SourceType.DIONAEA, dionaea.getSourceType());
        assertEquals("10.0.0.5", dionaea.getSourceIp());
        assertEquals(54321, dionaea.getSourcePort());
        assertEquals("10.0.0.10", dionaea.getDestinationIp());
        assertEquals(80, dionaea.getDestinationPort());

        assertEquals(SourceType.SENTRY_PEER, sentryPeer.getSourceType());
        assertEquals("10.0.0.5", sentryPeer.getSourceIp());
        assertEquals(5060, sentryPeer.getSourcePort());
        assertEquals("10.0.0.10", sentryPeer.getDestinationIp());
        assertEquals(5060, sentryPeer.getDestinationPort());
    }
}