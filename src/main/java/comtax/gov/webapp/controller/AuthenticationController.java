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
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/auth")
@Slf4j
@RequiredArgsConstructor
public class AuthenticationController {

	private final AuthenticationManager authManager;
	private final JwtService jwtService;
	private final AuthServiceDetails authServiceDetails;
	private final AuthService authService;
	private final LoginRateLimitFilter loginRateLimitFilter;
//	private final RedisTemplate<String, Object> redisTemplate;
	
	private final PasswordEncoder passwordEncoder;

	// ------------------ LOGIN ------------------
	@PostMapping("/login")
	public ResponseEntity<ApiResponse<AuthResponse>> login(@Valid @RequestBody AuthRequest request,
			HttpServletRequest httpRequest, HttpServletResponse response) {

		log.info("Login attempt for user: {}", request.getUsername());
		//log.info("Login attempt for user: {}", request.getCaptchaInput());
//		String pass="Test$123";
//		String enPass=passwordEncoder.encode(pass);
//		log.info(enPass);
		try {

			if (!request.getCaptchaInput().equalsIgnoreCase(request.getCaptcha())) {
				return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
						.body(new ApiResponse<>(HttpStatus.UNAUTHORIZED.value(), "Invalid CAPTCHA", null));

			}
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
	@PostMapping("/refresh-token")
	public ResponseEntity<ApiResponse<AuthResponse>> refresh(HttpServletRequest request, HttpServletResponse response) {

		log.info("Refresh token request received");
		

		Optional<String> refreshTokenOpt = CookieUtil.getCookieValue(request, "refresh_token");
		log.info("Refresh token request received::" + refreshTokenOpt);
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

	@GetMapping("/validate")
	public ResponseEntity<?> validateToken(@RequestHeader("Authorization") String authHeader) {
		if (authHeader == null || !authHeader.startsWith("Bearer ")) {
			return ResponseEntity.badRequest()
					.body(Map.of("valid", false, "reason", "missing_token", "message", "Missing Bearer token"));
		}

		String token = authHeader.substring(7);

		try {
			// 1️⃣ Check token signature & expiry
			boolean isValid = jwtService.validateToken(token);
			if (!isValid) {
				return ResponseEntity.status(HttpServletResponse.SC_UNAUTHORIZED).body(Map.of("valid", false, "reason",
						"expired_or_invalid", "message", "Token is expired or invalid"));
			}

			// 2️⃣ Extract username
			String username = jwtService.extractUsername(token).orElse(null);
			if (username == null) {
				return ResponseEntity.status(HttpServletResponse.SC_UNAUTHORIZED).body(Map.of("valid", false, "reason",
						"invalid_token", "message", "Unable to extract user from token"));
			}

			// 3️⃣ Check Redis for active session
			String redisKey = "auth:active_token:" + username;
//	        Object storedToken = redisTemplate.opsForValue().get(redisKey);

//	        if (storedToken == null || !storedToken.toString().equals(token)) {
//	            return ResponseEntity.status(HttpServletResponse.SC_UNAUTHORIZED).body(Map.of(
//	                    "valid", false,
//	                    "reason", "superseded",
//	                    "message", "A newer session is active for this user"
//	            ));
//	        }

			// 4️⃣ Token is valid and active
			// Optional: include username/roles
			// Claims claims = jwtService.getClaims(token);
			return ResponseEntity.ok(Map.of("valid", true
			// "username", claims.getSubject(),
			// "roles", claims.get("roles")
			));

		} catch (Exception e) {
			return ResponseEntity.status(HttpServletResponse.SC_INTERNAL_SERVER_ERROR)
					.body(Map.of("valid", false, "reason", "internal_error", "message", e.getMessage()));
		}
	}

	private String getClientIp(HttpServletRequest request) {
		String xfHeader = request.getHeader("X-Forwarded-For");
		if (xfHeader != null && !xfHeader.isBlank()) {
			return xfHeader.split(",")[0].trim();
		}
		return request.getRemoteAddr();
	}
}
