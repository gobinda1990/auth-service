package comtax.gov.webapp.model;

import java.time.LocalDate;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class HrmsUser {
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
    private Long boId;
}
