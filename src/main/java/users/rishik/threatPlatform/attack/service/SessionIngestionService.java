package users.rishik.threatPlatform.attack.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import tools.jackson.databind.ObjectMapper;
import users.rishik.threatPlatform.attack.dto.SessionRecord;
import users.rishik.threatPlatform.attack.mapper.SessionMapper;
import users.rishik.threatPlatform.attack.model.Session;
import users.rishik.threatPlatform.attack.repository.SessionRepository;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
public class SessionIngestionService {

    private final ObjectMapper objectMapper;
    private final SessionMapper sessionMapper;
    private final SessionRepository sessionRepository;

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
}