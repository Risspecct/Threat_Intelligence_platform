package users.rishik.threatPlatform.attack.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public record RawSentryPeerEvent(

        String timestamp,

        @JsonProperty("src_ip")
        String srcIp,

        @JsonProperty("src_port")
        Integer srcPort,

        @JsonProperty("dest_ip")
        String destIp,

        @JsonProperty("dest_port")
        Integer destPort,

        String type,

        @JsonProperty("transport_type")
        String transportType,

        @JsonProperty("sip_method")
        String sipMethod,

        @JsonProperty("sip_user_agent")
        String sipUserAgent,

        @JsonProperty("called_number")
        String calledNumber,

        @JsonProperty("event_uuid")
        String eventUuid

) {
}