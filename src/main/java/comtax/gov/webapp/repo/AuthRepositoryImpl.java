package comtax.gov.webapp.repo;

import java.util.Optional;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import comtax.gov.webapp.mapper.HrmsUserRowMapper;
import comtax.gov.webapp.model.HrmsUser;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Repository
@Slf4j
@RequiredArgsConstructor
public class AuthRepositoryImpl implements AuthRepository {
	
	private final JdbcTemplate jdbcTemplate;

	@Override
	public Optional<HrmsUser> findByHrmsCode(String userCode) {
		log.info("Enter into findByUserCode:--");		
		HrmsUser user = jdbcTemplate.queryForObject(AUTH_QRY, new HrmsUserRowMapper(), userCode);
        return Optional.ofNullable(user);
	}

}
