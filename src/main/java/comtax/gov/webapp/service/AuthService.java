package comtax.gov.webapp.service;

import comtax.gov.webapp.model.AuthResponse;
import comtax.gov.webapp.util.CookieUtil;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final JwtService jwtService;

    public AuthResponse generateAuthResponse(CustomUserDetails userDetails, HttpServletResponse response) {
        // Generate tokens
        String accessToken = jwtService.generateAccessToken(userDetails);
        String refreshToken = jwtService.generateRefreshToken(userDetails);

        // Set refresh token cookie only (secure attributes enabled)
        CookieUtil.addCookie(response, "refresh_token", refreshToken,
                (int) (jwtService.getRefreshExpiration() / 1000), true, false, "None", null);

        // Return AuthResponse with access token in body (not stored in cookie)
        return new AuthResponse(userDetails.getHrmsCode(),userDetails.getFullName(),
                userDetails.getCircleCd(), userDetails.getChargeCd(), userDetails.getEmail(),
                userDetails.getPhoneNo(),userDetails.getGpfNo(),userDetails.getPanNo(),userDetails.getBoId(),
                userDetails.getAuthorities().stream().map(auth -> auth.getAuthority().replace("ROLE_", ""))
                        .collect(Collectors.toSet()),
                accessToken, (int) (jwtService.getAccessExpiration() / 1000));
    }
}

