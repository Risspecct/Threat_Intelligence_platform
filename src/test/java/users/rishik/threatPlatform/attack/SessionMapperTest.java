package users.rishik.threatPlatform.attack;

import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;
import users.rishik.threatPlatform.attack.dto.SessionRecord;
import users.rishik.threatPlatform.attack.mapper.SessionMapper;
import users.rishik.threatPlatform.attack.model.Session;

import static org.junit.jupiter.api.Assertions.*;

class SessionMapperTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final SessionMapper mapper = new SessionMapper();

    @Test
    void shouldMapSessionRecordToSession() throws Exception {

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

        SessionRecord record =
                objectMapper.readValue(json, SessionRecord.class);

        Session session = mapper.toEntity(record);

        assertEquals("f0e3b9835983", session.getSessionId());
        assertEquals("2025-06-27 08:47:46.595149", session.getFirstSeen());
        assertEquals("2025-06-27 08:47:48.255063", session.getLastSeen());

        assertEquals(5, session.getTotalEvents());
        assertEquals(1, session.getLoginFailed());
        assertEquals(0, session.getLoginSuccess());

        assertEquals("431ef81b",
                session.getSourceIp().getAddress());

        assertEquals("52cf793a",
                session.getHoneypot().getAddress());
    }
}