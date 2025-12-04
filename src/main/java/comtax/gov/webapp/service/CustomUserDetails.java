package comtax.gov.webapp.service;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import comtax.gov.webapp.entities.Impact2User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import java.io.Serial;
import java.io.Serializable;
import java.time.LocalDate;
//import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Represents authenticated user details for Spring Security.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class CustomUserDetails implements UserDetails, Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    private String hrmsCode;
    private String passwd;
    private String fullName;
    private String email;
    private String phoneNo;
    private String usrStatusCd;
    private String usrLevelCd;
    private String desigCd;
    private String gpfNo;
    private String circleCd;
    private String chargeCd;
    private LocalDate usrPwdCreationDt;
    private LocalDate passwordExpireDt;
    private LocalDate dtOfJoin;
    private String panNo;
    private String boId;
//    private LocalDateTime logDt;

    private List<String> roles;

    public CustomUserDetails() {}
   
    public CustomUserDetails(Impact2User user) {
        this.hrmsCode = user.getHrmsCode();
        this.passwd = user.getPasswd();
        this.fullName = user.getFullName();
        this.email = user.getEmail();
        this.phoneNo = user.getPhoneNo();
        this.usrStatusCd = user.getUsrStatusCd();
        this.usrLevelCd = user.getUsrLevelCd();
        this.desigCd = user.getDesigCd();
        this.gpfNo = user.getGpfNo();
        this.circleCd = user.getCircleCd();
        this.chargeCd = user.getChargeCd();
        this.usrPwdCreationDt = user.getUsrPwdCreationDt();
        this.passwordExpireDt = user.getPasswordExpireDt();
        this.dtOfJoin = user.getDtOfJoin();
        this.panNo = user.getPanNo();
        this.boId = user.getBoId();
//        this.logDt = user.getLogDt();
        this.roles = user.getRoles() != null
                ? user.getRoles().stream().map(r -> r.getRoleName()).collect(Collectors.toList())
                : List.of();
    }

    // === Spring Security Methods ===
    @Override
    @JsonIgnore
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles == null
                ? List.of()
                : roles.stream()
                       .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                       .collect(Collectors.toList());
    }

    @Override
    @JsonIgnore
    public String getPassword() {
        return passwd;
    }

    @Override
    public String getUsername() {
        return hrmsCode;
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
        return "A".equalsIgnoreCase(usrStatusCd) || "L".equalsIgnoreCase(usrStatusCd);
    }
    // === Getters ===
    public String getHrmsCode() { return hrmsCode; }
    public String getFullName() { return fullName; }
    public String getEmail() { return email; }
    public String getPhoneNo() { return phoneNo; }
    public String getUsrStatusCd() { return usrStatusCd; }
    public String getUsrLevelCd() { return usrLevelCd; }
    public String getDesigCd() { return desigCd; }
    public String getGpfNo() { return gpfNo; }
    public String getCircleCd() { return circleCd; }
    public String getChargeCd() { return chargeCd; }
    public LocalDate getUsrPwdCreationDt() { return usrPwdCreationDt; }
    public LocalDate getPasswordExpireDt() { return passwordExpireDt; }
    public LocalDate getDtOfJoin() { return dtOfJoin; }
    public String getPanNo() { return panNo; }
    public String getBoId() { return boId; }
//    public LocalDateTime getLogDt() { return logDt; }
    public List<String> getRoles() { return roles; }
}
