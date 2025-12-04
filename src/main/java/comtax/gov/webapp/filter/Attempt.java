package comtax.gov.webapp.filter;

import java.io.Serializable;
import java.time.Instant;

public class Attempt implements Serializable {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private int count;
	private Instant timestamp;

	public Attempt() {
	}

	public Attempt(int count, Instant timestamp) {
		this.count = count;
		this.timestamp = timestamp;
	}

	public int getCount() {
		return count;
	}

	public void setCount(int count) {
		this.count = count;
	}

	public Instant getTimestamp() {
		return timestamp;
	}

	public void setTimestamp(Instant timestamp) {
		this.timestamp = timestamp;
	}
}
