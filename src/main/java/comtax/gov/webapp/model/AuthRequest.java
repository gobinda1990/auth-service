package comtax.gov.webapp.model;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthRequest {
	
	@NotBlank(message = "username is required")
	private String username;
	
	@NotBlank(message = "password is required")
	private String password;
	@NotBlank(message = "Captcha is required")
	private String captchaInput;
	
	private String captcha;

}
