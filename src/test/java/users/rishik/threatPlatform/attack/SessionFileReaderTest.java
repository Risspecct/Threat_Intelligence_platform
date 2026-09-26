//package users.rishik.threatPlatform.attack;
//
//import org.junit.jupiter.api.Test;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.boot.test.context.SpringBootTest;
//import users.rishik.threatPlatform.attack.service.SessionFileReader;
//
//import java.nio.file.Path;
//
//import static org.junit.jupiter.api.Assertions.assertTrue;
//
//@SpringBootTest
//class SessionFileReaderTest {
//
//    @Autowired
//    private SessionFileReader sessionFileReader;
//
//    @Test
//    void shouldIngestSessionFile() throws Exception {
//
//        Path file = Path.of(
//                "C:/Users/Rishi/Downloads/session_sample.jsonl"
//        );
//
//        int processed = sessionFileReader.ingestFile(file);
//
//        assertTrue(processed > 0);
//
//        System.out.println("Processed records: " + processed);
//    }
//}