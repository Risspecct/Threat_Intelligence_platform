package users.rishik.threatPlatform.attack.analysis.correlation;

import users.rishik.threatPlatform.attack.dto.SourceType;
import users.rishik.threatPlatform.attack.dto.ThreatObservation;

import java.util.ArrayList;
import java.util.List;

public class CorrelationEvidenceExtractor {

    public List<CorrelationEvidence> extract(
            ThreatObservation observation) {

        List<CorrelationEvidence> evidence = new ArrayList<>();

        add(evidence,
                CorrelationEvidenceType.SOURCE_IP,
                observation.getSourceIp());

        add(evidence,
                CorrelationEvidenceType.DESTINATION_IP,
                observation.getDestinationIp());

        add(evidence,
                CorrelationEvidenceType.DESTINATION_PORT,
                observation.getDestinationPort());

        add(evidence,
                CorrelationEvidenceType.PROTOCOL,
                observation.getProtocol());

        if (observation.getSourceType() == SourceType.COWRIE) {

            add(evidence,
                    CorrelationEvidenceType.COMMAND,
                    observation.getCommand());

            add(evidence,
                    CorrelationEvidenceType.FILE_HASH,
                    observation.getFileHash());

            add(evidence,
                    CorrelationEvidenceType.HASSH,
                    observation.getClientFingerprint());
        }

        if (observation.getSourceType() == SourceType.DIONAEA) {

            add(evidence,
                    CorrelationEvidenceType.SERVICE,
                    observation.getService());
        }

        if (observation.getSourceType() == SourceType.SENTRY_PEER) {

            add(evidence,
                    CorrelationEvidenceType.SIP_USER_AGENT,
                    observation.getSipUserAgent());

            add(evidence,
                    CorrelationEvidenceType.SIP_METHOD,
                    observation.getSipMethod());
        }

        return evidence;
    }

    private void add(
            List<CorrelationEvidence> evidence,
            CorrelationEvidenceType type,
            Object value) {

        if (value != null && !value.toString().isBlank()) {
            evidence.add(
                    new CorrelationEvidence(type, value.toString())
            );
        }
    }
}