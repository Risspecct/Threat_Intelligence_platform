package users.rishik.threatPlatform.attack.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.neo4j.core.Neo4jClient;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class ThreatGraphService {

    private final Neo4jClient neo4jClient;

    public List<String> findHoneypotsBySourceIp(String sourceIp) {

        String query = """
                MATCH (ip:SourceIP {address: $sourceIp})
                      -[:CREATED]->(s:Session)
                      -[:TARGETED]->(h:Honeypot)
                RETURN h.address AS address
                ORDER BY h.address
                """;

        return neo4jClient.query(query)
                .bind(sourceIp).to("sourceIp")
                .fetch()
                .all()
                .stream()
                .map(row -> (String) row.get("address"))
                .toList();
    }

    public List<Map<String, Object>> findMultiHoneypotSources() {

        String query = """
            MATCH (ip:SourceIP)-[:CREATED]->(s:Session)-[:TARGETED]->(h:Honeypot)
            WITH ip, count(DISTINCT h) AS honeypotCount
            WHERE honeypotCount > 1
            RETURN ip.address AS sourceIp, honeypotCount
            ORDER BY honeypotCount DESC
            """;

        return neo4jClient.query(query)
                .fetch()
                .all()
                .stream()
                .map(row -> Map.of(
                        "sourceIp", row.get("sourceIp"),
                        "honeypotCount", row.get("honeypotCount")
                ))
                .toList();
    }

    public List<Map<String, Object>> findSessionsBySourceIp(String sourceIp) {

        String query = """
            MATCH (ip:SourceIP {address: $sourceIp})
                  -[:CREATED]->(s:Session)
                  -[:TARGETED]->(h:Honeypot)
            RETURN
                s.sessionId AS sessionId,
                s.firstSeen AS firstSeen,
                s.lastSeen AS lastSeen,
                h.address AS honeypot
            ORDER BY s.firstSeen
            """;

        return neo4jClient.query(query)
                .bind(sourceIp).to("sourceIp")
                .fetch()
                .all()
                .stream()
                .map(row -> Map.of(
                        "sessionId", row.get("sessionId"),
                        "firstSeen", row.get("firstSeen"),
                        "lastSeen", row.get("lastSeen"),
                        "honeypot", row.get("honeypot")
                ))
                .toList();
    }
}