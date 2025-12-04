package comtax.gov.webapp.exception;

import org.springframework.dao.DataAccessException;
import org.springframework.http.*;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.BindException;
import org.springframework.web.*;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.request.async.AsyncRequestTimeoutException;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import comtax.gov.webapp.model.ApiResponse;
import lombok.extern.slf4j.Slf4j;

import java.nio.file.AccessDeniedException;
import java.sql.SQLException;
import java.util.stream.Collectors;

@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

	//private static final Logger logger = LogManager.getLogger(GlobalExceptionHandler.class);

	// -------------------- Client Errors --------------------

	@ExceptionHandler(UsernameNotFoundException.class)
	public ResponseEntity<ApiResponse<String>> handleAuthenticationErrors(UsernameNotFoundException ex) {
		String message = "Invalid username or password";
		log.warn("Authentication error: {}", message, ex.getMessage());

		return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
				.body(new ApiResponse<>(HttpStatus.UNAUTHORIZED.value(), message, ErrorCode.UNAUTHORIZED, null));
	}
	
	@ExceptionHandler(BadCredentialsException.class)
	public ResponseEntity<ApiResponse<String>> handleBadCredentials(BadCredentialsException ex) {
		String message = "Invalid username or password";
		log.warn("Authentication error: {}", message, ex.getMessage());

		return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
				.body(new ApiResponse<>(HttpStatus.UNAUTHORIZED.value(), message, ErrorCode.UNAUTHORIZED, null));
	}

	@ExceptionHandler(MethodArgumentNotValidException.class)
	public ResponseEntity<ApiResponse<String>> handleValidationErrors(MethodArgumentNotValidException ex) {
		String errorMsg = ex.getBindingResult().getFieldErrors().stream()
				.map(error -> error.getField() + ": " + error.getDefaultMessage()).collect(Collectors.joining(", "));

		String message = "Some fields have invalid values: " + errorMsg;
		log.warn("Validation error: {}", message);

		return ResponseEntity.badRequest().body(
				new ApiResponse<String>(HttpStatus.BAD_REQUEST.value(), message, ErrorCode.VALIDATION_ERROR, null));
	}

	@ExceptionHandler(BindException.class)
	public ResponseEntity<ApiResponse<String>> handleBindErrors(BindException ex) {
		String errorMsg = ex.getBindingResult().getFieldErrors().stream()
				.map(error -> error.getField() + ": " + error.getDefaultMessage()).collect(Collectors.joining(", "));
		String message = "Binding error: " + errorMsg;
		log.warn("Binding error: {}", message);

		return ResponseEntity.badRequest()
				.body(new ApiResponse<>(HttpStatus.BAD_REQUEST.value(), message, ErrorCode.VALIDATION_ERROR, null));
	}

	@ExceptionHandler(HttpMessageNotReadableException.class)
	public ResponseEntity<ApiResponse<String>> handleJsonParseError(HttpMessageNotReadableException ex) {
		log.warn("JSON parse error: {}", ex.getMessage(), ex.getMessage());
		String message = "Malformed JSON request. Please check your request body.";
		return ResponseEntity.badRequest()
				.body(new ApiResponse<>(HttpStatus.BAD_REQUEST.value(), message, ErrorCode.JSON_PARSE_ERROR, null));
	}

	@ExceptionHandler(HttpRequestMethodNotSupportedException.class)
	public ResponseEntity<ApiResponse<String>> handleMethodNotSupported(HttpRequestMethodNotSupportedException ex) {
		log.warn("Method not supported: {}. Supported: {}", ex.getMethod(), ex.getSupportedHttpMethods());
		String supportedMethods = ex.getSupportedHttpMethods() != null
				? ex.getSupportedHttpMethods().stream().map(HttpMethod::name).collect(Collectors.joining(", "))
				: "N/A";
		String message = "Request method '" + ex.getMethod() + "' not supported. Supported methods: "
				+ supportedMethods;

		return ResponseEntity.status(HttpStatus.METHOD_NOT_ALLOWED).body(
				new ApiResponse<>(HttpStatus.METHOD_NOT_ALLOWED.value(), message, ErrorCode.MISSING_PARAMETER, null));
	}

	@ExceptionHandler(NoHandlerFoundException.class)
	public ResponseEntity<ApiResponse<String>> handleNoHandler(NoHandlerFoundException ex) {
		log.warn("No handler found for request URL: {}", ex.getRequestURL(), ex.getMessage());
		String message = "The requested endpoint does not exist. Please check the URL.";
		return ResponseEntity.status(HttpStatus.NOT_FOUND)
				.body(new ApiResponse<>(HttpStatus.NOT_FOUND.value(), message, ErrorCode.RESOURCE_NOT_FOUND, null));
	}

	@ExceptionHandler(ResourceNotFoundException.class)
	public ResponseEntity<ApiResponse<String>> handleResourceNotFound(ResourceNotFoundException ex) {
		log.warn("Resource not found: {}", ex.getMessage(), ex.getMessage());
		String message = ex.getMessage() != null ? ex.getMessage() : "The requested resource could not be found.";
		return ResponseEntity.status(HttpStatus.NOT_FOUND)
				.body(new ApiResponse<>(HttpStatus.NOT_FOUND.value(), message, ErrorCode.RESOURCE_NOT_FOUND, null));
	}

	@ExceptionHandler(AccessDeniedException.class)
	public ResponseEntity<ApiResponse<String>> handleAccessDenied(AccessDeniedException ex) {
		log.warn("Access denied: {}", ex.getMessage(), ex.getMessage());
		String message = "You do not have permission to access this resource.";
		return ResponseEntity.status(HttpStatus.FORBIDDEN)
				.body(new ApiResponse<>(HttpStatus.FORBIDDEN.value(), message, ErrorCode.FORBIDDEN, null));
	}

	// -------------------- Server Errors --------------------

	@ExceptionHandler({ DataAccessException.class, DatabaseException.class, SQLException.class })
	public ResponseEntity<ApiResponse<String>> handleDatabaseError(Exception ex) {
		log.error("Database exception occurred", ex.getMessage());
		String message = "Database error occurred. Please try again later.";
		return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new ApiResponse<>(
				HttpStatus.INTERNAL_SERVER_ERROR.value(), message, ErrorCode.DB_CONNECTION_ERROR, null));
	}

	@ExceptionHandler(ServiceUnavailableException.class)
	public ResponseEntity<ApiResponse<String>> handleServiceUnavailable(ServiceUnavailableException ex) {
		log.error("Service unavailable", ex.getMessage());
		String message = "Service temporarily unavailable. Please try again later.";
		return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(new ApiResponse<>(
				HttpStatus.SERVICE_UNAVAILABLE.value(), message, ErrorCode.SERVICE_UNAVAILABLE, null));
	}

	@ExceptionHandler(EncryptionException.class)
	public ResponseEntity<ApiResponse<String>> handleEncryption(EncryptionException ex) {
		log.error("Encryption error occurred", ex.getMessage());
		String message = "An error occurred while securing your data. Please try again.";
		return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
				new ApiResponse<>(HttpStatus.INTERNAL_SERVER_ERROR.value(), message, ErrorCode.UNEXPECTED_ERROR, null));
	}

	@ExceptionHandler(AsyncRequestTimeoutException.class)
	public ResponseEntity<ApiResponse<String>> handleAsyncTimeout(AsyncRequestTimeoutException ex) {
		log.error("Async request timed out", ex.getMessage());
		String message = "The request timed out. Please try again later.";
		return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(new ApiResponse<>(
				HttpStatus.SERVICE_UNAVAILABLE.value(), message, ErrorCode.EXTERNAL_API_TIMEOUT, null));
	}

	// -------------------- Fallback --------------------

	@ExceptionHandler(Exception.class)
	public ResponseEntity<ApiResponse<String>> handleAll(Exception ex) {
		log.error("Unhandled error occurred", ex.getMessage());
		String message = "An unexpected error occurred. Please try again later.";
		return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
				new ApiResponse<>(HttpStatus.INTERNAL_SERVER_ERROR.value(), message, ErrorCode.UNEXPECTED_ERROR, null));
	}
}
