package users.rishik.threatPlatform.attack;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import users.rishik.threatPlatform.attack.analysis.feature.FeatureDistributionAnalyzer;
import users.rishik.threatPlatform.attack.analysis.feature.FeatureDistributionReport;
import users.rishik.threatPlatform.attack.service.RawCowrieEventReader;
import users.rishik.threatPlatform.attack.service.SessionBehaviorExtractor;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class FeatureDistributionAnalyzerTest {

    @Test
    void shouldAnalyzeBehavioralFeatureDistribution() throws Exception {

        String sessionOne = """
        {"ts":"2025-06-27 23:09:31.604633","eventid":"cowrie.login.success","session":"session-1","sensor":"sensor-1","group":1,"username":"root","password":"password","src_ip":"source-1","honeypot_ip":"honeypot-1"}
        {"ts":"2025-06-27 23:09:36.774454","eventid":"cowrie.command.input","session":"session-1","sensor":"sensor-1","group":1,"input":"whoami","src_ip":"source-1","honeypot_ip":"honeypot-1"}
        {"ts":"2025-06-27 23:09:40.774454","eventid":"cowrie.session.closed","session":"session-1","sensor":"sensor-1","group":1,"src_ip":"source-1","honeypot_ip":"honeypot-1"}
        """;

        String sessionTwo = """
        {"ts":"2025-06-27 23:10:31.604633","eventid":"cowrie.login.success","session":"session-2","sensor":"sensor-2","group":1,"username":"root","password":"password","src_ip":"source-2","honeypot_ip":"honeypot-2"}
        {"ts":"2025-06-27 23:10:36.774454","eventid":"cowrie.command.input","session":"session-2","sensor":"sensor-2","group":1,"input":"whoami","src_ip":"source-2","honeypot_ip":"honeypot-2"}
        {"ts":"2025-06-27 23:10:40.774454","eventid":"cowrie.command.input","session":"session-2","sensor":"sensor-2","group":1,"input":"uname -a","src_ip":"source-2","honeypot_ip":"honeypot-2"}
        {"ts":"2025-06-27 23:10:45.774454","eventid":"cowrie.session.closed","session":"session-2","sensor":"sensor-2","group":1,"src_ip":"source-2","honeypot_ip":"honeypot-2"}
        """;

        Path file = Files.createTempFile(
                "cowrie-analysis-test-",
                ".jsonl"
        );

        try {
            Files.writeString(
                    file,
                    sessionOne + sessionTwo
            );

            RawCowrieEventReader reader =
                    new RawCowrieEventReader(
                            new ObjectMapper()
                    );

            SessionBehaviorExtractor extractor =
                    new SessionBehaviorExtractor();

            FeatureDistributionAnalyzer analyzer =
                    new FeatureDistributionAnalyzer(
                            reader,
                            extractor
                    );

            FeatureDistributionReport report =
                    analyzer.analyze(file);

            assertEquals(
                    2,
                    report.sessionsAnalyzed()
            );

            assertEquals(
                    2,
                    report.sessionsWithCommands()
            );

            assertTrue(
                    report.topCommands().containsKey("whoami")
            );

            assertEquals(
                    2L,
                    report.topCommands().get("whoami")
            );

            assertEquals(
                    1L,
                    report.topCommands().get("uname -a")
            );

        } finally {
            Files.deleteIfExists(file);
        }
    }
}