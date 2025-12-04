package comtax.gov.webapp.entities;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "impact2_user_master")
@Getter
@Setter
public class Impact2User {

    @Id
    @Column(name = "hrms_code", length = 15)
    private String hrmsCode;

    @Column(name = "passwd", length = 100)
    private String passwd;

    @Column(name = "full_name", length = 120)
    private String fullName;

    @Column(name = "email", length = 150)
    private String email;

    @Column(name = "phone_no", length = 10)
    private String phoneNo;

    @Column(name = "usr_status_cd", length = 1)
    private String usrStatusCd;

    @Column(name = "usr_level_cd", length = 1)
    private String usrLevelCd;

    @Column(name = "desig_cd", length = 40)
    private String desigCd;

    @Column(name = "gpf_no", length = 30)
    private String gpfNo;

    @Column(name = "circle_cd", length = 2)
    private String circleCd;

    @Column(name = "charge_cd", length = 2)
    private String chargeCd;

    @Column(name = "usr_pwd_creation_dt")
    private LocalDate usrPwdCreationDt;

    @Column(name = "password_expire_dt")
    private LocalDate passwordExpireDt;

    @Column(name = "dt_of_join")
    private LocalDate dtOfJoin;

    @Column(name = "pan_no", length = 10)
    private String panNo;

    @Column(name = "bo_id", length = 30)
    private String boId;

    @Column(name = "log_dt")
    private LocalDateTime logDt;
    
 // 🔹 Many-to-Many relationship with roles
    @ManyToMany
    @JoinTable(
        name = "impact2_user_role_master",
        joinColumns = @JoinColumn(name = "hrms_id", referencedColumnName = "hrms_code"),
        inverseJoinColumns = @JoinColumn(name = "role_id", referencedColumnName = "role_id")
    )
    private Set<Impact2RoleMaster> roles = new HashSet<>();

  
}
