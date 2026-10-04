package users.rishik.threatPlatform.attack.mapper;

import users.rishik.threatPlatform.attack.dto.RawDionaeaEvent;
import users.rishik.threatPlatform.attack.dto.SourceType;
import users.rishik.threatPlatform.attack.dto.ThreatObservation;

import java.time.Instant;

public class DionaeaObservationMapper {

    public ThreatObservation map(RawDionaeaEvent event) {

        ThreatObservation observation = new ThreatObservation();

        observation.setObservationId(
                event.srcIp() + "-" + event.timestamp()
        );

        observation.setSourceType(SourceType.DIONAEA);

        if (event.timestamp() != null) {
            observation.setTimestamp(
                    Instant.parse(event.timestamp())
            );
        }

        observation.setSourceIp(event.srcIp());
        observation.setSourcePort(event.srcPort());

        observation.setDestinationIp(event.destIp());
        observation.setDestinationPort(event.destPort());

        if (event.connection() != null) {
            observation.setProtocol(
                    event.connection().transport()
            );

            observation.setService(
                    event.connection().protocol()
            );
        }

        observation.setActivityType(event.type());

        observation.setUsername(event.username());

        return observation;
    }
}