package comtax.gov.webapp.model;

import comtax.gov.webapp.exception.ErrorCode;

public class ApiResponse<T> {

	private int status;
	private String message;
	private ErrorCode errorCode;
	private T data;
	
	public ApiResponse(int status, String message, ErrorCode errorCode, T data) {
        this.status = status;
        this.message = message;
        this.errorCode = errorCode;
        this.data = data;
    }

    // Error with default message from ErrorCode
    public ApiResponse(int status, ErrorCode errorCode) {
        this(status, errorCode.getDefaultMessage(), errorCode, null);
    }

    // Error with custom message
    public ApiResponse(int status, String message, ErrorCode errorCode) {
        this(status, message, errorCode, null);
    }

    // Success with data
    public ApiResponse(int status, String message, T data) {
        this(status, message, null, data);
    }

	public int getStatus() {
		return status;
	}

	public void setStatus(int status) {
		this.status = status;
	}

	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}

	public ErrorCode getErrorCode() {
		return errorCode;
	}

	public void setErrorCode(ErrorCode errorCode) {
		this.errorCode = errorCode;
	}

	public T getData() {
		return data;
	}

	public void setData(T data) {
		this.data = data;
	}
    
    

}
