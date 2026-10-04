package users.rishik.threatPlatform.attack.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public record RawDionaeaDocument(
        RawDionaeaEvent _source
) {
}