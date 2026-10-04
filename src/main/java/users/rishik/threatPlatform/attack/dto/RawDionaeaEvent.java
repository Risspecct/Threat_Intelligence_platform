package users.rishik.threatPlatform.attack.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public record RawDionaeaEvent(

        String timestamp,

        @JsonProperty("@timestamp")
        String eventTimestamp,

        @JsonProperty("src_ip")
        String srcIp,

        @JsonProperty("src_port")
        Integer srcPort,

        @JsonProperty("dest_ip")
        String destIp,

        @JsonProperty("dest_port")
        Integer destPort,

        String type,

        String username,

        String password,

        Connection connection
) {

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Connection(
            String protocol,
            String transport,
            String type
    ) {
    }
}