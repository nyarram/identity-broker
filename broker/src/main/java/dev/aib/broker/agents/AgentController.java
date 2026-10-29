package dev.aib.broker.agents;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/admin/agents")
class AgentController {

    record RegisterAgentRequest(
            String name,
            @JsonProperty("public_jwk") Map<String, Object> publicJwk,
            @JsonProperty("allowed_audiences") List<String> allowedAudiences) {}

    record AgentResponse(
            String id,
            String name,
            @JsonProperty("key_id") String keyId,
            @JsonProperty("allowed_audiences") List<String> allowedAudiences,
            @JsonProperty("created_at") Instant createdAt,
            @JsonProperty("disabled_at") Instant disabledAt) {

        static AgentResponse of(Agent a) {
            return new AgentResponse(
                    a.id(), a.name(), a.publicKey().getKeyID(), a.allowedAudiences(), a.createdAt(), a.disabledAt());
        }
    }

    private final AgentService agents;

    AgentController(AgentService agents) {
        this.agents = agents;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    AgentResponse register(@RequestBody RegisterAgentRequest request) {
        return AgentResponse.of(agents.register(request.name(), request.publicJwk(), request.allowedAudiences()));
    }

    @GetMapping("/{id}")
    AgentResponse get(@PathVariable String id) {
        return AgentResponse.of(agents.get(id));
    }

    @PostMapping("/{id}/disable")
    AgentResponse disable(@PathVariable String id) {
        agents.disable(id);
        return AgentResponse.of(agents.get(id));
    }
}
