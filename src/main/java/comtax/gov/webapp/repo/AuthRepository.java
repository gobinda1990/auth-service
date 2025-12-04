package comtax.gov.webapp.repo;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import comtax.gov.webapp.entities.Impact2User;

public interface AuthRepository  extends JpaRepository<Impact2User, String>{	
	
	
	Optional<Impact2User> findByHrmsCode(String userCode);

}
