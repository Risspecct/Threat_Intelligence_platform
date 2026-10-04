package users.rishik.threatPlatform.attack.mapper;

import users.rishik.threatPlatform.attack.dto.CrossSourceEvidence;
import users.rishik.threatPlatform.attack.dto.ThreatObservation;

public class CrossSourceEvidenceMapper {

    public CrossSourceEvidence map(ThreatObservation observation) {

        return new CrossSourceEvidence(
                observation.getSourceIp(),
                observation.getTimestamp(),
                observation.getDestinationIp(),
                observation.getDestinationPort(),
                observation.getProtocol()
        );
    }
}