package users.rishik.threatPlatform.attack.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class MultiHoneypotSource {

    private String sourceIp;
    private long honeypotCount;
}