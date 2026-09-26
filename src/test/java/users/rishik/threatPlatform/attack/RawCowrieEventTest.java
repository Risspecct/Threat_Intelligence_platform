package users.rishik.threatPlatform.attack;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import users.rishik.threatPlatform.attack.dto.RawCowrieEvent;

import static org.junit.jupiter.api.Assertions.*;

class RawCowrieEventTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void shouldDeserializeCowrieLoginEvent() throws Exception {

        String json = """
                {
                  "ts": "2025-06-27 23:09:31.604633",
                  "src_port": null,
                  "dst_ip": null,
                  "dst_port": null,
                  "eventid": "cowrie.login.success",
                  "session": "e500e363a13b",
                  "sensor": "e9f16d233101",
                  "group": 1,
                  "username": "root",
                  "password": "yhtcAdmin",
                  "input": null,
                  "message": "login attempt [root/yhtcAdmin] succeeded",
                  "url": null,
                  "protocol": null,
                  "hassh": null,
                  "shasum": null,
                  "filename": null,
                  "destfile": null,
                  "outfile": null,
                  "version": null,
                  "src_ip": "cfb0efc2",
                  "honeypot_ip": "62c6f987"
                }
                """;

        RawCowrieEvent event =
                objectMapper.readValue(json, RawCowrieEvent.class);

        assertEquals("e500e363a13b", event.session());
        assertEquals("cowrie.login.success", event.eventid());
        assertEquals("root", event.username());
        assertEquals("yhtcAdmin", event.password());
        assertEquals("cfb0efc2", event.srcIp());
        assertEquals("62c6f987", event.honeypotIp());
    }
}