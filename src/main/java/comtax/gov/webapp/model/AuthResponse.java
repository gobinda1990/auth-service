package comtax.gov.webapp.model;

import java.util.Set;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor

public class AuthResponse {	
	
	private String hrmsCd;
	private String fullName;
	private String circleCd;
	private String chargeCd;
	private String emailId;
	private String phoneNo;	
    private String gpfNo;
    private String panNo;
    private String boId;
	private Set<String> roles;
    private String accessToken;
    private int expiresIn; // access token expiry in seconds

}
