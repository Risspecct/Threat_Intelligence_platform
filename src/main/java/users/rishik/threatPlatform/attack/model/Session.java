package users.rishik.threatPlatform.attack.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.neo4j.core.schema.Id;
import org.springframework.data.neo4j.core.schema.Node;
import org.springframework.data.neo4j.core.schema.Relationship;

@Getter
@Setter
@NoArgsConstructor
@Node("Session")
public class Session {

    public Session(String sessionId) {
        this.sessionId = sessionId;
    }

    @Id
    private String sessionId;

    private String firstSeen;
    private String lastSeen;

    private int totalEvents;

    private int loginFailed;
    private int loginSuccess;

    private int commandInput;
    private int commandFailed;
    private int commandSuccess;

    private int fileDownload;
    private int fileDownloadFailed;
    private int fileUpload;

    @Relationship(type = "CREATED", direction = Relationship.Direction.INCOMING)
    private SourceIp sourceIp;

    @Relationship(type = "TARGETED", direction = Relationship.Direction.OUTGOING)
    private Honeypot honeypot;
}