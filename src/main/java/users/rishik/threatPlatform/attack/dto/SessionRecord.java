package users.rishik.threatPlatform.attack.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
public class SessionRecord {

    private String session;

    @JsonProperty("src_ip")
    private String srcIp;

    @JsonProperty("honeypot_ip")
    private String honeypotIp;

    @JsonProperty("first_seen")
    private String firstSeen;

    @JsonProperty("last_seen")
    private String lastSeen;

    @JsonProperty("total_events")
    private int totalEvents;

    @JsonProperty("cnt_login_failed")
    private int loginFailed;

    @JsonProperty("cnt_login_success")
    private int loginSuccess;

    @JsonProperty("cnt_command_input")
    private int commandInput;

    @JsonProperty("cnt_command_failed")
    private int commandFailed;

    @JsonProperty("cnt_command_success")
    private int commandSuccess;

    @JsonProperty("cnt_file_download")
    private int fileDownload;

    @JsonProperty("cnt_file_download_failed")
    private int fileDownloadFailed;

    @JsonProperty("cnt_file_upload")
    private int fileUpload;
}