package com.oauth.server.exception;

import com.oauth.server.dto.response.ErrorResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.stream.Collectors;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(OAuth2Exception.class)
    public ResponseEntity<ErrorResponse> handleOAuth2Exception(OAuth2Exception ex) {
        OAuth2ErrorCode errorCode = ex.getErrorCode();
        ErrorResponse body = new ErrorResponse(errorCode.getValue(), ex.getErrorDescription());
        ResponseEntity.BodyBuilder builder = ResponseEntity.status(errorCode.getHttpStatus());
        if (errorCode == OAuth2ErrorCode.INVALID_CLIENT) {
            builder.header(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"oauth-server\"");
        }
        return builder.body(body);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidation(MethodArgumentNotValidException ex) {
        String description = ex.getBindingResult().getFieldErrors().stream()
                .map(this::formatFieldError)
                .collect(Collectors.joining("; "));
        if (description.isBlank()) {
            description = "request validation failed";
        }
        ErrorResponse body = new ErrorResponse(OAuth2ErrorCode.INVALID_REQUEST.getValue(), description);
        return ResponseEntity.status(OAuth2ErrorCode.INVALID_REQUEST.getHttpStatus()).body(body);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGeneric(Exception ex) {
        ErrorResponse body = new ErrorResponse(OAuth2ErrorCode.SERVER_ERROR.getValue(), "unexpected server error");
        return ResponseEntity.status(OAuth2ErrorCode.SERVER_ERROR.getHttpStatus()).body(body);
    }

    private String formatFieldError(FieldError error) {
        return error.getField() + " " + (error.getDefaultMessage() == null ? "is invalid" : error.getDefaultMessage());
    }
}
