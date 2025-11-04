package comtax.gov.webapp.exception;

public class ServiceUnavailableException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	public ServiceUnavailableException(String message, Throwable cause) {
		super(message, cause);
	}

}
