package users.rishik.threatPlatform.attack.mapper;

import users.rishik.threatPlatform.attack.dto.RawSentryPeerEvent;
import users.rishik.threatPlatform.attack.dto.SourceType;
import users.rishik.threatPlatform.attack.dto.ThreatObservation;

import java.time.Instant;

public class SentryPeerObservationMapper {

    public ThreatObservation map(RawSentryPeerEvent event) {
        ThreatObservation observation = new ThreatObservation();

        observation.setObservationId(event.eventUuid());
        observation.setSourceType(SourceType.SENTRY_PEER);

        if (event.eventTimestamp() != null) {
            observation.setTimestamp(Instant.parse(event.eventTimestamp()));
        }

        observation.setSourceIp(event.srcIp());
        observation.setSourcePort(event.srcPort());
        observation.setDestinationIp(event.destIp());
        observation.setDestinationPort(event.destPort());
        observation.setProtocol(event.transportType());
        observation.setActivityType(event.type());

        observation.setSipMethod(event.sipMethod());
        observation.setSipUserAgent(event.sipUserAgent());
        observation.setCalledNumber(event.calledNumber());

        return observation;
    }
}