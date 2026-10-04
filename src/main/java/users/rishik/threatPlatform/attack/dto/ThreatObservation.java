package users.rishik.threatPlatform.attack.dto;

import lombok.Data;

import java.time.Instant;

@Data
public class ThreatObservation {

    private String observationId;

    private SourceType sourceType;

    private Instant timestamp;

    private String sensorId;

    private String sourceIp;
    private Integer sourcePort;

    private String destinationIp;
    private Integer destinationPort;

    private String protocol;

    private String activityType;

    private String sessionId;

    // Behavioral evidence
    private String command;
    private String fileHash;
    private String downloadUrl;

    // Client / service information
    private String clientFingerprint;
    private String service;

    // Authentication
    private String username;
    private String loginOutcome;

    // SIP-specific evidence
    private String sipMethod;
    private String sipUserAgent;
    private String calledNumber;
}