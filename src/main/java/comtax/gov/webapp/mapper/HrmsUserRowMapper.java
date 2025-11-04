package comtax.gov.webapp.mapper;

import java.sql.ResultSet;
import java.sql.SQLException;
import org.springframework.jdbc.core.RowMapper;

import comtax.gov.webapp.model.HrmsUser;

public class HrmsUserRowMapper implements RowMapper<HrmsUser> {

	@Override
	public HrmsUser mapRow(ResultSet rs, int rowNum) throws SQLException {		
		return new HrmsUser(rs.getString("hrms_code"), rs.getString("passwd"), rs.getString("full_name"),
				rs.getString("email"), rs.getString("phone_no"), rs.getString("usr_status_cd"), null,
				rs.getString("desig_cd"), rs.getString("gpf_no"), rs.getString("circle_cd"), rs.getString("charge_cd"),
				rs.getDate("usr_pwd_creation_dt") != null ? rs.getDate("usr_pwd_creation_dt").toLocalDate() : null,
				rs.getDate("password_expire_dt") != null ? rs.getDate("password_expire_dt").toLocalDate() : null,
				rs.getDate("dt_of_join") != null ? rs.getDate("dt_of_join").toLocalDate() : null,
				rs.getString("pan_no"), rs.getLong("bo_id"));
	}

}
