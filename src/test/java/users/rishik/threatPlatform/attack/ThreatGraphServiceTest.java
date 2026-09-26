package users.rishik.threatPlatform.attack;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import users.rishik.threatPlatform.attack.dto.MultiHoneypotSource;
import users.rishik.threatPlatform.attack.dto.SourceSession;
import users.rishik.threatPlatform.attack.service.ThreatGraphService;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class ThreatGraphServiceTest {

    @Autowired
    private ThreatGraphService threatGraphService;

    @Test
    void shouldFindHoneypotsForSourceIp() {

        String sourceIp = "431ef81b";

        List<String> honeypots =
                threatGraphService.findHoneypotsBySourceIp(sourceIp);

        assertNotNull(honeypots);
        assertFalse(honeypots.isEmpty());

        System.out.println("Honeypots: " + honeypots);
    }

    @Test
    void shouldFindSourcesThatContactedMultipleHoneypots() {

        List<MultiHoneypotSource> results =
                threatGraphService.findMultiHoneypotSources();

        assertNotNull(results);
        assertFalse(results.isEmpty());

        results.forEach(System.out::println);
    }

    @Test
    void shouldReturnSourceSessionsChronologically() {

        List<MultiHoneypotSource> sources =
                threatGraphService.findMultiHoneypotSources();

        assertFalse(sources.isEmpty());

        String sourceIp =
                (String) sources.getFirst().getSourceIp();

        List<SourceSession> sessions =
                threatGraphService.findSessionsBySourceIp(sourceIp);

        assertFalse(sessions.isEmpty());

        sessions.forEach(System.out::println);
    }
}