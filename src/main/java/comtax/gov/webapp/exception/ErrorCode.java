package comtax.gov.webapp.exception;

public enum  ErrorCode {
	
	// 1xxx: Validation / Request Errors
    VALIDATION_ERROR("ERR-1001", "Validation failed"),
    MISSING_PARAMETER("ERR-1002", "Missing or invalid parameter"),
    JSON_PARSE_ERROR("ERR-1003", "Malformed JSON request"),

    // 2xxx: Database Errors
    DB_CONNECTION_ERROR("ERR-2001", "Database connection error"),
    DB_QUERY_ERROR("ERR-2002", "Database query error"),
    DB_INTEGRITY_ERROR("ERR-2003", "Data integrity violation"),

    // 3xxx: Security / Authorization Errors
    UNAUTHORIZED("ERR-3001", "Authentication failed"),
    FORBIDDEN("ERR-3002", "Access denied"),
    TOKEN_EXPIRED("ERR-3003", "Token expired or invalid"),
    INVALID_TOKEN("ERR-3004", "invalid token"),
    // 4xxx: Resource / Business Logic Errors
    RESOURCE_NOT_FOUND("ERR-4001", "Resource not found"),
    DUPLICATE_RESOURCE("ERR-4002", "Duplicate resource"),
    BUSINESS_RULE_VIOLATION("ERR-4003", "Business rule violation"),

    // 5xxx: External / Service Errors
    SERVICE_UNAVAILABLE("ERR-5001", "Service unavailable"),
    EXTERNAL_API_TIMEOUT("ERR-5002", "External API timeout"),

    // 9xxx: Generic / Fallback
    UNEXPECTED_ERROR("ERR-9999", "Unexpected server error");

    private final String code;
    private final String defaultMessage;

    ErrorCode(String code, String defaultMessage) {
        this.code = code;
        this.defaultMessage = defaultMessage;
    }

    public String getCode() {
        return code;
    }

    public String getDefaultMessage() {
        return defaultMessage;
    }

}
