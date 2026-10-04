package users.rishik.threatPlatform.attack.mapper;

import users.rishik.threatPlatform.attack.dto.RawCowrieEvent;
import users.rishik.threatPlatform.attack.dto.SourceType;
import users.rishik.threatPlatform.attack.dto.ThreatObservation;

import java.time.Instant;

public class CowrieObservationMapper {

    public ThreatObservation map(RawCowrieEvent event) {

        ThreatObservation observation = new ThreatObservation();

        observation.setObservationId(
                event.session() + "-" + event.ts()
        );

        observation.setSourceType(SourceType.COWRIE);

        if (event.ts() != null) {
            observation.setTimestamp(Instant.parse(event.ts()));
        }

        observation.setSensorId(event.sensor());

        observation.setSourceIp(event.srcIp());
        observation.setSourcePort(event.srcPort());

        observation.setDestinationIp(event.dstIp());
        observation.setDestinationPort(event.dstPort());

        observation.setProtocol(event.protocol());

        observation.setActivityType(event.eventid());

        observation.setSessionId(event.session());

        observation.setCommand(event.input());
        observation.setFileHash(event.shasum());

        observation.setClientFingerprint(event.hassh());

        observation.setUsername(event.username());

        return observation;
    }
}