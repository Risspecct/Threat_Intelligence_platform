package users.rishik.threatPlatform.attack.dto;

import java.time.LocalDateTime;
import java.util.List;

public record SessionBehavior(

        String sessionId,

        String sourceIp,

        String honeypotIp,

        String sensor,

        Integer group,

        LocalDateTime firstSeen,

        LocalDateTime lastSeen,

        List<String> eventSequence,

        List<String> commandSequence,

        boolean loginSuccess,

        boolean loginFailure,

        String hassh,

        String clientVersion,

        List<String> fileHashes,

        List<String> downloadUrls,

        List<String> destinationIps,

        List<Integer> destinationPorts
) {
}
