package comtax.gov.webapp.repo;

import java.util.Optional;
import comtax.gov.webapp.model.HrmsUser;

public interface AuthRepository {
	
	String AUTH_QRY="SELECT  u.hrms_code, u.full_name, u.email,u.phone_no,u.usr_status_cd,u.usr_level_cd,"
			+ " r.role_name,u.desig_cd,u.gpf_no,u.circle_cd,u.charge_cd,u.usr_pwd_creation_dt,u.password_expire_dt,"
			+ " u.dt_of_join,u.pan_no,u.bo_id FROM hrms_users u JOIN user_roles r  ON u.usr_level_cd = r.role_id"
			+ " WHERE u.hrms_code = 'YOUR_HRMS_CODE' ";
	
	Optional<HrmsUser> findByHrmsCode(String userCode);

}
