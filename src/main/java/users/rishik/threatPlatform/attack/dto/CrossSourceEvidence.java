package users.rishik.threatPlatform.attack.dto;

import java.time.Instant;

public record CrossSourceEvidence(
        String sourceIp,
        Instant timestamp,
        String destinationIp,
        Integer destinationPort,
        String protocol
) {
}