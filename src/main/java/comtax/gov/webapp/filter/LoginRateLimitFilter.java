package comtax.gov.webapp.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.TimeUnit;

/**
 * IP-based login rate limiter filter using Redis. Limits login attempts per IP
 * address for a 15-minute window.
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class LoginRateLimitFilter extends OncePerRequestFilter {

	private static final int MAX_ATTEMPTS = 10;
	private static final Duration WINDOW = Duration.ofMinutes(1);

//	private final RedisTemplate<String, Attempt> redisTemplate;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		log.info(request.getRequestURI());

		if ("/api/auth/login".equals(request.getRequestURI()) && "POST".equalsIgnoreCase(request.getMethod())) {

			String clientIp = getClientIp(request);
			String redisKey = "login:attempt:" + clientIp;

//			Attempt attempt = redisTemplate.opsForValue().get(redisKey);
//			if (attempt == null) {
//				attempt = new Attempt(0, Instant.now());
//			}

			// Reset window if expired
//			if (Instant.now().isAfter(attempt.getTimestamp().plus(WINDOW))) {
//				attempt = new Attempt(0, Instant.now());
//			}

//			if (attempt.getCount() >= MAX_ATTEMPTS) {
//				long remainingMinutes = Duration.between(Instant.now(), attempt.getTimestamp().plus(WINDOW))
//						.toMinutes();
//				if (remainingMinutes < 0)
//					remainingMinutes = 0;
//
//				log.warn("IP {} blocked due to too many login attempts", clientIp);
//
//				response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
//				response.setContentType("application/json;charset=UTF-8");
//
//				String message = String.format(
//						"{\"status\": %d, \"error\": \"%s\", \"message\": \"%s\", \"remainingMinutes\": %d}",
//						HttpStatus.TOO_MANY_REQUESTS.value(), "Too Many Requests",
//						"Too many login attempts. Please try again after " + remainingMinutes + " minutes.",
//						remainingMinutes);
//
//				response.getWriter().write(message);
//				response.getWriter().flush();
//				return;
//			}
//
//			// Increment and persist attempt count
//			attempt.setCount(attempt.getCount() + 1);
//			redisTemplate.opsForValue().set(redisKey, attempt, WINDOW.toMinutes(), TimeUnit.MINUTES);

//			log.info("Login attempt {} from IP {}", attempt.getCount(), clientIp);
		}

		filterChain.doFilter(request, response);
	}

	private String getClientIp(HttpServletRequest request) {
		String xfHeader = request.getHeader("X-Forwarded-For");
		if (xfHeader != null && !xfHeader.isBlank()) {
			return xfHeader.split(",")[0].trim();
		}
		return request.getRemoteAddr();
	}

	/** Reset attempts for IP (call after successful login) */
	public void resetAttempts(String clientIp) {
//		redisTemplate.delete("login:attempt:" + clientIp);
		log.info("Login attempts reset for IP {}", clientIp);
	}
}
