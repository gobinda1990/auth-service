package comtax.gov.webapp.entities;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import java.util.*;



@Entity
@Table(name = "usr_cd")
@Getter
@Setter
public class UserEntity {

    @Id
    @Column(name = "usr_cd", length = 30)
    private String userCode;

    @Column(name = "hrms_cd", length = 15, nullable = false)
    private String hrmsCode;

    @Column(name = "usr_nm", length = 120)
    private String userName;

    @Column(name = "passwd", length = 100, nullable = false)
    private String password;

    @Column(name = "desig", length = 2, nullable = false)
    private String designation;

    @Column(name = "circle_cd", length = 2)
    private String circleCode;

    @Column(name = "charge_cd", length = 2)
    private String chargeCode;

    @Column(name = "pwd_cr_dt")
    private Date passwordCreatedDate;

    @Column(name = "pwd_exp_dt")
    private Date passwordExpiryDate;

    @Column(name = "dt_join_cur")
    private Date joinDate;

    @Column(name = "bio_location_tg", length = 1)
    private String bioLocationTag;

    @Column(name = "bio_location_tg_dt")
    private Date bioLocationTagDate;

    // 🔑 Many-to-Many with Role via user_role_map
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "user_role_map",
            joinColumns = {
                    @JoinColumn(name = "usr_cd", referencedColumnName = "usr_cd"),
                    @JoinColumn(name = "hrms_cd", referencedColumnName = "hrms_cd")
            },
            inverseJoinColumns = @JoinColumn(name = "role_cd", referencedColumnName = "role_cd") // ✅ point to role table
    )
    private Set<RoleEntity> roles = new HashSet<>();

    // getters & setters
    
    
    
    
}

