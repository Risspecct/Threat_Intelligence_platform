package users.rishik.threatPlatform.attack.repository;

import org.springframework.data.neo4j.repository.Neo4jRepository;
import org.springframework.stereotype.Repository;
import users.rishik.threatPlatform.attack.model.Session;

@Repository
public interface SessionRepository extends Neo4jRepository<Session, String> {
}