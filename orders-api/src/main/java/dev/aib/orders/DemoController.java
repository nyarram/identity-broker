package dev.aib.orders;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/** Demo support, available only with the demo key (see {@link DemoKeyFilter}). */
@RestController
class DemoController {

    private final OrderStore orders;

    DemoController(OrderStore orders) {
        this.orders = orders;
    }

    @PostMapping("/admin/reset")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    void reset() {
        orders.reset();
    }
}
