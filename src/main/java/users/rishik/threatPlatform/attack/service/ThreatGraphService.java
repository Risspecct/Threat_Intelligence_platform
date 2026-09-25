package users.rishik.threatPlatform.attack.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.neo4j.core.Neo4jClient;
import org.springframework.stereotype.Service;

import java.util.List;

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
}