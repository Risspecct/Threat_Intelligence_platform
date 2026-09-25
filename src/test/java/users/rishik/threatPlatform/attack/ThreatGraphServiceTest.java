package users.rishik.threatPlatform.attack;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import users.rishik.threatPlatform.attack.service.ThreatGraphService;

import java.util.List;
import java.util.Map;

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

        List<Map<String, Object>> results =
                threatGraphService.findMultiHoneypotSources();

        assertNotNull(results);
        assertFalse(results.isEmpty());

        results.forEach(System.out::println);
    }

    @Test
    void shouldReturnSourceSessionsChronologically() {

        List<Map<String, Object>> sources =
                threatGraphService.findMultiHoneypotSources();

        assertFalse(sources.isEmpty());

        String sourceIp =
                (String) sources.get(0).get("sourceIp");

        List<Map<String, Object>> sessions =
                threatGraphService.findSessionsBySourceIp(sourceIp);

        assertFalse(sessions.isEmpty());

        sessions.forEach(System.out::println);
    }
}