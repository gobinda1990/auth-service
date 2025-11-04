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
	
	private String userId;
	private String userNm;
	private String hrmsCd;
	private String circleCd;
	private String chargeCd;
	private String emailId;
	private Set<String> roles;
    private String accessToken;
    private int expiresIn; // access token expiry in seconds

}
