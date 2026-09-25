package users.rishik.threatPlatform.attack;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import users.rishik.threatPlatform.attack.model.Honeypot;
import users.rishik.threatPlatform.attack.model.Session;
import users.rishik.threatPlatform.attack.model.SourceIp;
import users.rishik.threatPlatform.attack.repository.SessionRepository;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class SessionRepositoryTest {

    @Autowired
    private SessionRepository sessionRepository;

    @Test
    void shouldPersistSessionGraph() {

        Session session = new Session("test-session-001");

        session.setFirstSeen("2025-06-27 08:47:46.595149");
        session.setLastSeen("2025-06-27 08:47:48.255063");
        session.setTotalEvents(5);
        session.setLoginFailed(1);

        session.setSourceIp(
                new SourceIp("test-source-001")
        );

        session.setHoneypot(
                new Honeypot("test-honeypot-001")
        );

        Session saved = sessionRepository.save(session);

        assertNotNull(saved);
        assertEquals("test-session-001", saved.getSessionId());
    }
}