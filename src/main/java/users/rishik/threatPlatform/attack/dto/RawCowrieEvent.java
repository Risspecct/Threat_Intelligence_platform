package users.rishik.threatPlatform.attack.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record RawCowrieEvent(

        String ts,

        @JsonProperty("src_port")
        Integer srcPort,

        @JsonProperty("dst_ip")
        String dstIp,

        @JsonProperty("dst_port")
        Integer dstPort,

        String eventid,

        String session,

        String sensor,

        Integer group,

        String username,

        String password,

        String input,

        String message,

        String url,

        String protocol,

        String hassh,

        @JsonProperty("hasshAlgorithms")
        String hasshAlgorithms,

        String fingerprint,

        String filename,

        String destfile,

        String outfile,

        String shasum,

        Long size,

        Long duration,

        String version,

        @JsonProperty("src_ip")
        String srcIp,

        @JsonProperty("honeypot_ip")
        String honeypotIp
) {
}