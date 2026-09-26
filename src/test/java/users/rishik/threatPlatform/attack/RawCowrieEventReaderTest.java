package users.rishik.threatPlatform.attack;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import users.rishik.threatPlatform.attack.dto.RawCowrieEvent;
import users.rishik.threatPlatform.attack.service.RawCowrieEventReader;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class RawCowrieEventReaderTest {

    @Test
    void shouldReadRawCowrieEventsFromJsonl() throws Exception {

        String firstEvent = """
        {"ts":"2025-06-27 23:09:31.604633","eventid":"cowrie.login.success","session":"session-1","sensor":"sensor-1","group":1,"username":"root","password":"password","src_ip":"source-1","honeypot_ip":"honeypot-1"}
        """;

        String secondEvent = """
        {"ts":"2025-06-27 23:09:36.774454","eventid":"cowrie.command.input","session":"session-1","sensor":"sensor-1","group":1,"input":"whoami","src_ip":"source-1","honeypot_ip":"honeypot-1"}
        """;

        Path file = Files.createTempFile("cowrie-test-", ".jsonl");

        try {
            Files.writeString(
                    file,
                    firstEvent + System.lineSeparator() + secondEvent
            );

            RawCowrieEventReader reader =
                    new RawCowrieEventReader(new ObjectMapper());

            List<RawCowrieEvent> events = new ArrayList<>();

            reader.read(file, events::add);

            assertEquals(2, events.size());

            assertEquals(
                    "cowrie.login.success",
                    events.get(0).eventid()
            );

            assertEquals(
                    "cowrie.command.input",
                    events.get(1).eventid()
            );

            assertEquals(
                    "session-1",
                    events.get(0).session()
            );

        } finally {
            Files.deleteIfExists(file);
        }
    }
}