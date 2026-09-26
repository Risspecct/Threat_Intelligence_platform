package users.rishik.threatPlatform.attack;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import users.rishik.threatPlatform.attack.service.RawCowrieEventReader;
import users.rishik.threatPlatform.attack.service.SessionBehaviorExtractor;
import users.rishik.threatPlatform.attack.service.SessionEventProcessor;

import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicInteger;

class RealCowriePipelineTest {

    @Test
    @Disabled("Manual dataset analysis")
    void processRealCowrieDataset() throws Exception {

        Path file = Path.of(
                System.getProperty("user.home"),
                "Downloads",
                "2025-06-27-events.json"
        );

        RawCowrieEventReader reader =
                new RawCowrieEventReader(new ObjectMapper());

        SessionEventProcessor processor =
                new SessionEventProcessor(
                        new SessionBehaviorExtractor()
                );

        AtomicInteger totalBehaviors =
                new AtomicInteger();

        AtomicInteger closedBehaviors =
                new AtomicInteger();

        AtomicInteger maximumActiveSessions =
                new AtomicInteger();

        reader.read(
                file,
                event -> {

                    int before =
                            processor.activeSessionCount();

                    processor.accept(
                            event,
                            behavior -> {
                                totalBehaviors.incrementAndGet();

                                if ("cowrie.session.closed"
                                        .equals(event.eventid())) {
                                    closedBehaviors.incrementAndGet();
                                }
                            }
                    );

                    int after =
                            processor.activeSessionCount();

                    maximumActiveSessions.updateAndGet(
                            current -> Math.max(
                                    current,
                                    Math.max(before, after)
                            )
                    );
                }
        );

        int remainingSessions =
                processor.activeSessionCount();

        processor.finishRemaining(
                behavior -> totalBehaviors.incrementAndGet()
        );

        System.out.println();
        System.out.println(
                "========== Real Cowrie Pipeline =========="
        );
        System.out.println(
                "SessionBehavior objects: "
                        + totalBehaviors.get()
        );
        System.out.println(
                "Closed sessions finalized: "
                        + closedBehaviors.get()
        );
        System.out.println(
                "Sessions finalized at EOF: "
                        + remainingSessions
        );
        System.out.println(
                "Maximum active sessions: "
                        + maximumActiveSessions.get()
        );
        System.out.println(
                "==========================================="
        );
    }
}