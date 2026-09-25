package users.rishik.threatPlatform.attack.mapper;

import org.springframework.stereotype.Component;
import users.rishik.threatPlatform.attack.dto.SessionRecord;
import users.rishik.threatPlatform.attack.model.Honeypot;
import users.rishik.threatPlatform.attack.model.Session;
import users.rishik.threatPlatform.attack.model.SourceIp;

@Component
public class SessionMapper {

    public Session toEntity(SessionRecord record) {

        Session session = new Session(record.getSession());

        session.setFirstSeen(record.getFirstSeen());
        session.setLastSeen(record.getLastSeen());
        session.setTotalEvents(record.getTotalEvents());

        session.setLoginFailed(record.getLoginFailed());
        session.setLoginSuccess(record.getLoginSuccess());

        session.setCommandInput(record.getCommandInput());
        session.setCommandFailed(record.getCommandFailed());
        session.setCommandSuccess(record.getCommandSuccess());

        session.setFileDownload(record.getFileDownload());
        session.setFileDownloadFailed(record.getFileDownloadFailed());
        session.setFileUpload(record.getFileUpload());

        session.setSourceIp(new SourceIp(record.getSrcIp()));
        session.setHoneypot(new Honeypot(record.getHoneypotIp()));

        return session;
    }
}