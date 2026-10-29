package dev.aib.broker.audit;

import com.fasterxml.jackson.annotation.JsonProperty;
import dev.aib.broker.audit.AuditLog.AuditEvent;
import dev.aib.broker.audit.AuditLog.Verification;
import dev.aib.broker.support.ApiException;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/admin/audit")
class AuditController {

    static final int MAX_PAGE_SIZE = 500;

    record AuditPage(List<AuditEvent> events, @JsonProperty("next_after") Long nextAfter) {}

    record VerificationResponse(
            boolean valid,
            @JsonProperty("events_checked") long eventsChecked,
            @JsonProperty("first_broken_seq") Long firstBrokenSeq,
            String problem) {

        static VerificationResponse of(Verification v) {
            return new VerificationResponse(v.valid(), v.eventsChecked(), v.firstBrokenSeq(), v.problem());
        }
    }

    private final AuditLog audit;

    AuditController(AuditLog audit) {
        this.audit = audit;
    }

    /** Events in order; pass the returned next_after to read the next page. */
    @GetMapping
    AuditPage list(@RequestParam(defaultValue = "0") long after, @RequestParam(defaultValue = "100") int limit) {
        if (limit < 1 || limit > MAX_PAGE_SIZE) {
            throw ApiException.badRequest("limit must be between 1 and " + MAX_PAGE_SIZE);
        }
        List<AuditEvent> events = audit.list(after, limit);
        return new AuditPage(events, events.size() == limit ? events.getLast().seq() : null);
    }

    @GetMapping("/verify")
    VerificationResponse verify() {
        return VerificationResponse.of(audit.verify());
    }
}
