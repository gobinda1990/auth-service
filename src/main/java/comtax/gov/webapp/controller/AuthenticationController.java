package comtax.gov.webapp.controller;

import comtax.gov.webapp.filter.LoginRateLimitFilter;
import comtax.gov.webapp.model.ApiResponse;
import comtax.gov.webapp.model.AuthRequest;
import comtax.gov.webapp.model.AuthResponse;
import comtax.gov.webapp.service.AuthService;
import comtax.gov.webapp.service.AuthServiceDetails;
import comtax.gov.webapp.service.CustomUserDetails;
import comtax.gov.webapp.service.JwtService;
import comtax.gov.webapp.util.CookieUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/auth")
@Slf4j
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class AuthenticationController {

	private final AuthenticationManager authManager;
	private final JwtService jwtService;
	private final AuthServiceDetails authServiceDetails;
	private final AuthService authService;
	private final LoginRateLimitFilter loginRateLimitFilter;

	// ------------------ LOGIN ------------------
	@PostMapping("/login")
	public ResponseEntity<ApiResponse<AuthResponse>> login(@Valid @RequestBody AuthRequest request,
			HttpServletRequest httpRequest, HttpServletResponse response) {

		log.info("Login attempt for user: {}", request.getUsername());

		try {
			var auth = authManager.authenticate(
					new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));

			CustomUserDetails userDetails = (CustomUserDetails) auth.getPrincipal();
			AuthResponse authResponse = authService.generateAuthResponse(userDetails, response);

			// Reset failed login attempts for IP
			String clientIp = getClientIp(httpRequest);
			loginRateLimitFilter.resetAttempts(clientIp);

			return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK.value(), "Login successful", authResponse));

		} catch (Exception e) {
			log.warn("Login failed for user {}: {}", request.getUsername(), e.getMessage());
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
					.body(new ApiResponse<>(HttpStatus.UNAUTHORIZED.value(), "Invalid username or password", null));
		}
	}

	// ------------------ REFRESH TOKEN ------------------
	@PostMapping("/refresh")
	public ResponseEntity<ApiResponse<AuthResponse>> refresh(HttpServletRequest request, HttpServletResponse response) {

		log.info("Refresh token request received");

		Optional<String> refreshTokenOpt = CookieUtil.getCookieValue(request, "refresh_token");
//		log.info("Refresh token request received::"+refreshTokenOpt);
		if (refreshTokenOpt.isEmpty()) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
					.body(new ApiResponse<>(HttpStatus.UNAUTHORIZED.value(), "Missing refresh token", null));
		}

		String token = refreshTokenOpt.get();

		if (!jwtService.validateToken(token)) {
			String msg = jwtService.isTokenExpired(token) ? "Refresh token expired" : "Invalid refresh token";

			return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
					.body(new ApiResponse<>(HttpStatus.UNAUTHORIZED.value(), msg, null));
		}

		String username = jwtService.extractUsername(token)
				.orElseThrow(() -> new UsernameNotFoundException("User not found"));

		CustomUserDetails userDetails = (CustomUserDetails) authServiceDetails.loadUserByUsername(username);
		AuthResponse authResponse = authService.generateAuthResponse(userDetails, response);

		return ResponseEntity
				.ok(new ApiResponse<>(HttpStatus.OK.value(), "Token refreshed successfully", authResponse));
	}

	// ------------------ LOGOUT ------------------
	@PostMapping("/logout")
	public ResponseEntity<ApiResponse<Map<String, Object>>> logout(HttpServletRequest request,
			HttpServletResponse response) {

		log.info("User requested logout");

		Optional<String> refreshTokenOpt = CookieUtil.getCookieValue(request, "refresh_token");
		refreshTokenOpt.ifPresent(token -> {
			if (jwtService.validateToken(token)) {
				log.info("Refresh token valid; consider blacklisting if tokens are persisted.");
			}
		});

		CookieUtil.deleteCookie(response, "access_token", null);
		CookieUtil.deleteCookie(response, "refresh_token", null);

		Map<String, Object> body = Map.of("status", "success", "message", "You have been logged out successfully");

		return ResponseEntity.ok(new ApiResponse<>(HttpStatus.OK.value(), "Logout successful", body));
	}

	private String getClientIp(HttpServletRequest request) {
		String xfHeader = request.getHeader("X-Forwarded-For");
		if (xfHeader != null && !xfHeader.isBlank()) {
			return xfHeader.split(",")[0].trim();
		}
		return request.getRemoteAddr();
	}
}
