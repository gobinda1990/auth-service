package comtax.gov.webapp.entities;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;


@Entity
@Table(name = "role")
@Getter
@Setter
public class RoleEntity {

    @Id
    @Column(name = "role_cd", length = 10)
    private String roleCode;

    @Column(name = "role_name", length = 50, nullable = false)
    private String roleName;

    // getters & setters
}

