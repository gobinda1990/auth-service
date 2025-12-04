package comtax.gov.webapp.filter;

import comtax.gov.webapp.service.AuthServiceDetails;
import comtax.gov.webapp.service.CustomUserDetails;
import comtax.gov.webapp.service.JwtService;
import comtax.gov.webapp.util.CookieUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

@Component
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

	private final JwtService jwtService;
	private final AuthServiceDetails authServiceDetails;
//	private final RedisTemplate<String, Object> redisTemplate;

	private static final String USER_SESSION_PREFIX = "auth:active_token:";
	private static final long EXPIRY_WARNING_THRESHOLD_MS = 2 * 60 * 1000; // 2 minutes

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		try {
			Optional<String> accessTokenOpt = jwtService.extractTokenFromRequest(request, "access_token");
			Optional<String> refreshTokenOpt = jwtService.extractTokenFromRequest(request, "refresh_token");

			if (accessTokenOpt.isPresent()) {
				String accessToken = accessTokenOpt.get();

				if (!jwtService.validateToken(accessToken)) {
					SecurityContextHolder.clearContext();
					filterChain.doFilter(request, response);
					return;
				}

				String username = jwtService.extractUsername(accessToken).orElse(null);
				if (username == null) {
					filterChain.doFilter(request, response);
					return;
				}

				// Verify this is the active session in Redis
				String redisKey = USER_SESSION_PREFIX + username;
//				Object storedToken = redisTemplate.opsForValue().get(redisKey);

//				if (storedToken == null || !storedToken.toString().equals(accessToken)) {
//					log.warn("Rejected old token for user '{}': newer session active.", username);
//					sendJsonError(response, HttpServletResponse.SC_UNAUTHORIZED,
//							"You have been logged out because you logged in from another device.");
//					return;
//				}

				// Authenticated and valid
				authenticateUser(username);

				// Add expiry warning headers if nearing expiration
				long remainingMs = jwtService.getRemainingValidity(accessToken);
				if (remainingMs > 0 && remainingMs <= EXPIRY_WARNING_THRESHOLD_MS) {
					response.setHeader("X-Session-Expiry-Warning", "true");
					response.setHeader("X-Session-Expires-In-Seconds", String.valueOf(remainingMs / 1000));
				}
			}

			// --- Handle refresh token if access token expired ---
			else if (refreshTokenOpt.isPresent()) {
				String refreshToken = refreshTokenOpt.get();

				if (jwtService.validateToken(refreshToken)) {
					String username = jwtService.extractUsername(refreshToken).orElse(null);
					if (username != null) {
						CustomUserDetails userDetails = (CustomUserDetails) authServiceDetails
								.loadUserByUsername(username);

						String newAccessToken = jwtService.generateAccessToken(userDetails);

						// Replace Redis stored token
//						redisTemplate.opsForValue().set(USER_SESSION_PREFIX + username, newAccessToken);
						CookieUtil.addCookie(response, "access_token", newAccessToken,
								(int) (jwtService.getAccessExpiration() / 1000), true, true, "Strict", null);

						authenticateUser(username);
						log.info("Refreshed token for user {}", username);
					}
				}
			}

		} catch (Exception ex) {
			log.error("JWT auth filter error: {}", ex.getMessage());
			SecurityContextHolder.clearContext();
		}

		filterChain.doFilter(request, response);
	}

	private void authenticateUser(String username) {
		if (SecurityContextHolder.getContext().getAuthentication() == null) {
			CustomUserDetails userDetails = (CustomUserDetails) authServiceDetails.loadUserByUsername(username);

			UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null,
					userDetails.getAuthorities());
			SecurityContextHolder.getContext().setAuthentication(authToken);
		}
	}

	private void sendJsonError(HttpServletResponse response, int status, String message) throws IOException {
		response.setStatus(status);
		response.setContentType("application/json;charset=UTF-8");
		response.getWriter().write(
				String.format("{\"status\": %d, \"error\": \"Unauthorized\", \"message\": \"%s\"}", status, message));
		response.getWriter().flush();
	}

	@Override
	protected boolean shouldNotFilter(HttpServletRequest request) {
		String path = request.getRequestURI();
		// Skip auth filter for login, registration, and public endpoints
		return path.startsWith("/auth") || path.startsWith("/public");
	}
}
