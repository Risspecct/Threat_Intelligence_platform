package users.rishik.threatPlatform.attack;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import users.rishik.threatPlatform.attack.model.Session;
import users.rishik.threatPlatform.attack.service.SessionIngestionService;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class SessionIngestionServiceTest {

    @Autowired
    private SessionIngestionService ingestionService;

    @Test
    void shouldIngestSession() throws Exception {

        String json = """
                {
                  "session": "f0e3b9835983",
                  "src_ip": "431ef81b",
                  "honeypot_ip": "52cf793a",
                  "first_seen": "2025-06-27 08:47:46.595149",
                  "last_seen": "2025-06-27 08:47:48.255063",
                  "total_events": 5,
                  "cnt_login_failed": 1,
                  "cnt_login_success": 0,
                  "cnt_command_input": 0,
                  "cnt_command_failed": 0,
                  "cnt_command_success": 0,
                  "cnt_file_download": 0,
                  "cnt_file_download_failed": 0,
                  "cnt_file_upload": 0
                }
                """;

        Session session = ingestionService.ingest(json);

        assertEquals("f0e3b9835983", session.getSessionId());
        assertEquals("431ef81b", session.getSourceIp().getAddress());
        assertEquals("52cf793a", session.getHoneypot().getAddress());
    }
}