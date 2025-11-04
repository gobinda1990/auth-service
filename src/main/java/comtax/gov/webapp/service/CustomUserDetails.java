package comtax.gov.webapp.service;

import comtax.gov.webapp.entities.UserEntity;
import comtax.gov.webapp.entities.RoleEntity;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import java.io.Serial;
import java.io.Serializable;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Data
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class CustomUserDetails implements UserDetails, Serializable {

	@Serial
	private static final long serialVersionUID = 1L;

	private String userCode;
	private String password;
	private String hrmsCode;
	private String circleCode;
	private String chargeCode;

	@JsonProperty("username")
	private String userName;

	private List<String> roles;

	public CustomUserDetails(UserEntity user) {
		this.userCode = user.getUserCode();
		this.password = user.getPassword();
		this.hrmsCode = user.getHrmsCode();
		this.circleCode = user.getCircleCode();
		this.chargeCode = user.getChargeCode();
		this.userName = user.getUserName();
		this.roles = user.getRoles().stream().map(RoleEntity::getRoleCode).collect(Collectors.toList());
	}

	@Override
	@JsonIgnore
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return roles == null ? List.of()
				: roles.stream().map(role -> new SimpleGrantedAuthority("ROLE_" + role)).collect(Collectors.toList());
	}

	@Override
	public String getUsername() {
		return userCode;
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return true;
	}

	public String getEmail() {
		return userName;
	}
}
