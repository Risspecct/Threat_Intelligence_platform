package users.rishik.threatPlatform.attack;

import org.junit.jupiter.api.Test;
import users.rishik.threatPlatform.attack.dto.RawCowrieEvent;
import users.rishik.threatPlatform.attack.dto.SessionBehavior;
import users.rishik.threatPlatform.attack.service.SessionAccumulator;
import users.rishik.threatPlatform.attack.service.SessionBehaviorExtractor;

import static org.junit.jupiter.api.Assertions.*;

class SessionAccumulatorTest {

    @Test
    void shouldAccumulateEventsAndBuildBehavior() {

        SessionAccumulator accumulator =
                new SessionAccumulator();

        RawCowrieEvent login = new RawCowrieEvent(
                "2025-06-27 23:09:31.604633", // 1 ts
                null,                          // 2 srcPort
                null,                          // 3 dstIp
                null,                          // 4 dstPort
                "cowrie.login.success",       // 5 eventid
                "session-1",                   // 6 session
                "sensor-1",                    // 7 sensor
                1,                             // 8 group
                "root",                        // 9 username
                "password",                    // 10 password
                null,                          // 11 input
                "login succeeded",             // 12 message
                null,                          // 13 url
                null,                          // 14 protocol
                "hassh-123",                  // 15 hassh
                null,                          // 16 hasshAlgorithms
                null,                          // 17 fingerprint
                null,                          // 18 filename
                null,                          // 19 destfile
                null,                          // 20 outfile
                null,                          // 21 shasum
                null,                          // 22 size
                null,                          // 23 duration
                null,                          // 24 version
                "source-1",                    // 25 srcIp
                "honeypot-1"                   // 26 honeypotIp
        );

        RawCowrieEvent command = new RawCowrieEvent(
                "2025-06-27 23:09:36.774454", // 1 ts
                null,                          // 2 srcPort
                null,                          // 3 dstIp
                null,                          // 4 dstPort
                "cowrie.command.input",       // 5 eventid
                "session-1",                   // 6 session
                "sensor-1",                    // 7 sensor
                1,                             // 8 group
                null,                          // 9 username
                null,                          // 10 password
                "whoami",                      // 11 input
                null,                          // 12 message
                null,                          // 13 url
                null,                          // 14 protocol
                null,                          // 15 hassh
                null,                          // 16 hasshAlgorithms
                null,                          // 17 fingerprint
                null,                          // 18 filename
                null,                          // 19 destfile
                null,                          // 20 outfile
                null,                          // 21 shasum
                null,                          // 22 size
                null,                          // 23 duration
                null,                          // 24 version
                "source-1",                    // 25 srcIp
                "honeypot-1"                   // 26 honeypotIp
        );

        accumulator.add(login);
        accumulator.add(command);

        assertEquals(2, accumulator.size());

        SessionBehavior behavior =
                accumulator.build(new SessionBehaviorExtractor());

        assertEquals("session-1", behavior.sessionId());
        assertTrue(behavior.loginSuccess());
        assertEquals(1, behavior.commandSequence().size());
        assertEquals("whoami", behavior.commandSequence().getFirst());
    }
}