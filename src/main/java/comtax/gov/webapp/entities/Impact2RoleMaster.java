package comtax.gov.webapp.entities;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "impact2_role_master")
@Getter
@Setter
public class Impact2RoleMaster {

    @Id
    @Column(name = "role_id", length = 50)
    private String roleId;

    @Column(name = "role_name", length = 100)
    private String roleName;

    // Reverse mapping to users
    @ManyToMany(mappedBy = "roles")
    private Set<Impact2User> users = new HashSet<>();

    
}

