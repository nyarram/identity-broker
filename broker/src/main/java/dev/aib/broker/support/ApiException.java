package dev.aib.broker.support;

import org.springframework.http.HttpStatus;

/** An error returned to API callers as {@code {"error": ..., "error_description": ...}}. */
public class ApiException extends RuntimeException {

    private final HttpStatus status;
    private final String error;

    public ApiException(HttpStatus status, String error, String description) {
        super(description);
        this.status = status;
        this.error = error;
    }

    public static ApiException badRequest(String description) {
        return new ApiException(HttpStatus.BAD_REQUEST, "invalid_request", description);
    }

    public static ApiException notFound(String description) {
        return new ApiException(HttpStatus.NOT_FOUND, "not_found", description);
    }

    public HttpStatus status() {
        return status;
    }

    public String error() {
        return error;
    }
}
