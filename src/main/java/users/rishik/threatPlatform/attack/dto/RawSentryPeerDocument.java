package users.rishik.threatPlatform.attack.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public record RawSentryPeerDocument(
        RawSentryPeerEvent _source
) {}