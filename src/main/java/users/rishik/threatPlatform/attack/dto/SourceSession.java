package users.rishik.threatPlatform.attack.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class SourceSession {

    private String sessionId;
    private String firstSeen;
    private String lastSeen;
    private String honeypot;
}