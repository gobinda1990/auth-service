package comtax.gov.webapp.repo;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import comtax.gov.webapp.entities.UserEntity;

public interface UserRepository extends JpaRepository<UserEntity, String>{
	
	Optional<UserEntity> findByUserCode(String userCode);

}
