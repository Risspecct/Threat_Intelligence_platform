package users.rishik.threatPlatform.attack.analysis.correlation;

public enum CorrelationEvidenceType {

    SOURCE_IP,
    TEMPORAL_PROXIMITY,
    DESTINATION_IP,
    DESTINATION_PORT,
    PROTOCOL,

    COMMAND,
    FILE_HASH,
    HASSH,
    CLIENT_FINGERPRINT,

    SERVICE,
    SIP_USER_AGENT,
    SIP_METHOD;

    public boolean isStrongBehavioralEvidence() {
        return switch (this) {
            case COMMAND,
                 FILE_HASH,
                 HASSH,
                 CLIENT_FINGERPRINT ->
                    true;

            default ->
                    false;
        };
    }

    public boolean isContextualEvidence() {
        return switch (this) {
            case SOURCE_IP,
                 DESTINATION_IP,
                 DESTINATION_PORT,
                 PROTOCOL,
                 SERVICE,
                 SIP_METHOD,
                 SIP_USER_AGENT ->
                    true;

            default ->
                    false;
        };
    }
}