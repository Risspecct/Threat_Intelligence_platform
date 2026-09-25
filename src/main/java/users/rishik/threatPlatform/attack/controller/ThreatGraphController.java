package users.rishik.threatPlatform.attack.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import users.rishik.threatPlatform.attack.dto.MultiHoneypotSource;
import users.rishik.threatPlatform.attack.dto.SourceSession;
import users.rishik.threatPlatform.attack.service.ThreatGraphService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/graph")
@RequiredArgsConstructor
@Tag(
        name = "Threat Graph",
        description = "Graph-based threat intelligence queries"
)
public class ThreatGraphController {

    private final ThreatGraphService threatGraphService;

    @GetMapping("/sources/{sourceIp}/honeypots")
    @Operation(
            summary = "Find honeypots contacted by a source IP",
            description = "Returns the honeypots targeted by sessions originating from the specified source IP."
    )
    public List<String> findHoneypotsBySourceIp(
            @Parameter(
                    description = "Source IP address",
                    example = "431ef81b"
            )
            @PathVariable String sourceIp
    ) {
        return threatGraphService.findHoneypotsBySourceIp(sourceIp);
    }

    @GetMapping("/sources/multi-honeypot")
    @Operation(
            summary = "Find sources that contacted multiple honeypots",
            description = "Returns source IPs that have interacted with more than one distinct honeypot."
    )
    public List<MultiHoneypotSource> findMultiHoneypotSources() {
        return threatGraphService.findMultiHoneypotSources();
    }

    @GetMapping("/sources/{sourceIp}/sessions")
    @Operation(
            summary = "Find sessions for a source IP",
            description = "Returns sessions for a source IP ordered chronologically by first-seen time."
    )
    public List<SourceSession> findSessionsBySourceIp(
            @Parameter(
                    description = "Source IP address",
                    example = "431ef81b"
            )
            @PathVariable String sourceIp
    ) {
        return threatGraphService.findSessionsBySourceIp(sourceIp);
    }
}