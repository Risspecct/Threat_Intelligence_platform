package users.rishik.threatPlatform.attack.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.neo4j.core.schema.Id;
import org.springframework.data.neo4j.core.schema.Node;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@Node("SourceIP")
public class SourceIp {

    @Id
    private String address;
}