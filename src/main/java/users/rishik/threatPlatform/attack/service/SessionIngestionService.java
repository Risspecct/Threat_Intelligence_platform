package users.rishik.threatPlatform.attack.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.data.neo4j.core.Neo4jClient;
import tools.jackson.databind.ObjectMapper;
import users.rishik.threatPlatform.attack.dto.SessionRecord;
import users.rishik.threatPlatform.attack.mapper.SessionMapper;
import users.rishik.threatPlatform.attack.model.Session;
import users.rishik.threatPlatform.attack.repository.SessionRepository;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class SessionIngestionService {

    private final ObjectMapper objectMapper;
    private final SessionMapper sessionMapper;
    private final SessionRepository sessionRepository;
    private final Neo4jClient neo4jClient;

    public Session ingest(String jsonLine) throws IOException {

        SessionRecord record =
                objectMapper.readValue(jsonLine, SessionRecord.class);

        Session session =
                sessionMapper.toEntity(record);

        return sessionRepository.save(session);
    }

    public void ingestBatch(List<String> jsonLines) throws IOException {

        List<Session> sessions = new ArrayList<>(jsonLines.size());

        for (String jsonLine : jsonLines) {

            SessionRecord record =
                    objectMapper.readValue(jsonLine, SessionRecord.class);

            Session session =
                    sessionMapper.toEntity(record);

            sessions.add(session);
        }

        sessionRepository.saveAll(sessions);
    }

    public void ingestBatchBulk(List<String> jsonLines) throws IOException {

        List<Session> sessions = new ArrayList<>(jsonLines.size());

        for (String jsonLine : jsonLines) {

            SessionRecord record =
                    objectMapper.readValue(jsonLine, SessionRecord.class);

            Session session =
                    sessionMapper.toEntity(record);

            sessions.add(session);
        }

        List<Map<String, Object>> parameters = sessions.stream()
                .map(this::toParameters)
                .toList();

        neo4jClient.query("""
            UNWIND $sessions AS session

            MERGE (source:SourceIP {address: session.sourceIp})
            MERGE (honeypot:Honeypot {address: session.honeypotIp})

            CREATE (s:Session {
                sessionId: session.sessionId,
                firstSeen: session.firstSeen,
                lastSeen: session.lastSeen,
                totalEvents: session.totalEvents,
                loginFailed: session.loginFailed,
                loginSuccess: session.loginSuccess,
                commandInput: session.commandInput,
                commandFailed: session.commandFailed,
                commandSuccess: session.commandSuccess,
                fileDownload: session.fileDownload,
                fileDownloadFailed: session.fileDownloadFailed,
                fileUpload: session.fileUpload
            })

            CREATE (source)-[:CREATED]->(s)
            CREATE (s)-[:TARGETED]->(honeypot)
            """)
                .bind(parameters)
                .to("sessions")
                .run();
    }

    private Map<String, Object> toParameters(Session session) {

        Map<String, Object> parameters = new HashMap<>();

        parameters.put("sessionId", session.getSessionId());
        parameters.put("sourceIp", session.getSourceIp().getAddress());
        parameters.put("honeypotIp", session.getHoneypot().getAddress());
        parameters.put("firstSeen", session.getFirstSeen());
        parameters.put("lastSeen", session.getLastSeen());
        parameters.put("totalEvents", session.getTotalEvents());
        parameters.put("loginFailed", session.getLoginFailed());
        parameters.put("loginSuccess", session.getLoginSuccess());
        parameters.put("commandInput", session.getCommandInput());
        parameters.put("commandFailed", session.getCommandFailed());
        parameters.put("commandSuccess", session.getCommandSuccess());
        parameters.put("fileDownload", session.getFileDownload());
        parameters.put("fileDownloadFailed", session.getFileDownloadFailed());
        parameters.put("fileUpload", session.getFileUpload());

        return parameters;
    }
}