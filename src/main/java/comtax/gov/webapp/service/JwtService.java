
package comtax.gov.webapp.service;

import io.jsonwebtoken.*;
import jakarta.servlet.http.HttpServletRequest;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;
import comtax.gov.webapp.security.RsaKeyProvider;
import java.util.*;
import java.util.stream.Collectors;

@Service
@Getter
@Setter
@Slf4j
public class JwtService {

	private final long accessExpiration; // milliseconds
	private final long refreshExpiration; // milliseconds
	private final RsaKeyProvider keyProvider;

	public JwtService(@Value("${jwt.access-expiration}") Long accessExpiration,
			@Value("${jwt.refresh-expiration}") Long refreshExpiration, RsaKeyProvider keyProvider) {
		this.accessExpiration = accessExpiration;
		this.refreshExpiration = refreshExpiration;
		this.keyProvider = keyProvider;
	}

	// ------------------ TOKEN GENERATION ------------------

	public String generateAccessToken(CustomUserDetails userDetails) {
		return generateToken(userDetails, accessExpiration, "access");
	}

	public String generateRefreshToken(CustomUserDetails userDetails) {
		return generateToken(userDetails, refreshExpiration, "refresh");
	}

	private String generateToken(CustomUserDetails userDetails, long expirationMillis, String type) {
		long nowMillis = System.currentTimeMillis();
		Date now = new Date(nowMillis);
		Date expiryDate = new Date(nowMillis + expirationMillis);

		Map<String, Object> claims = new HashMap<>();
		claims.put("hrmsCd", userDetails.getHrmsCode());
		claims.put("fullName", userDetails.getFullName());
		claims.put("circleCd", userDetails.getCircleCd());
		claims.put("chargeCd", userDetails.getChargeCd());
		claims.put("emailId", userDetails.getEmail());
		claims.put("phoneNo", userDetails.getPhoneNo());
		claims.put("gpfNo", userDetails.getGpfNo());
		claims.put("panNo", userDetails.getPanNo());
		claims.put("boId", userDetails.getBoId());
		claims.put("tokenType", type);
		claims.put("roles",
				userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet()));

		return Jwts.builder().setClaims(claims).setSubject(userDetails.getUsername()).setIssuedAt(now)
				.setExpiration(expiryDate).signWith(keyProvider.getPrivateKey(), SignatureAlgorithm.RS256).compact();
	}

	// ------------------ TOKEN VALIDATION ------------------

	public boolean validateToken(String token) {
		try {
			Claims claims = parseClaims(token);
			return claims.getExpiration().after(new Date());
		} catch (ExpiredJwtException ex) {
			log.error("JWT expired: {}", ex.getMessage());
			return false;
		} catch (JwtException | IllegalArgumentException ex) {
			log.error("Invalid JWT: {}", ex.getMessage());
			return false;
		}
	}

	public boolean isTokenExpired(String token) {
		return parseClaimsOptional(token).map(claims -> claims.getExpiration().before(new Date())).orElse(true);
	}

	public long getRemainingValidity(String token) {
		return parseClaimsOptional(token).map(claims -> claims.getExpiration().getTime() - System.currentTimeMillis())
				.orElse(0L);
	}

	// ------------------ CLAIM EXTRACTION ------------------

	public Optional<String> extractUsername(String token) {
		return parseClaimsOptional(token).map(Claims::getSubject);
	}

	public Optional<String> extractUserCode(String token) {
		return parseClaimsOptional(token).map(c -> (String) c.get("userCode"));
	}

	public Set<String> extractRoles(String token) {
		return parseClaimsOptional(token).map(claims -> {
			Object roles = claims.get("roles");
			if (roles instanceof Collection<?> col) {
				return col.stream().filter(String.class::isInstance).map(String.class::cast)
						.collect(Collectors.toSet());
			}
			return Set.<String>of();
		}).orElse(Set.of());
	}

	public Optional<String> extractTokenType(String token) {
		return parseClaimsOptional(token).map(c -> (String) c.get("tokenType"));
	}

	// ------------------ REQUEST TOKEN EXTRACTION ------------------

	public Optional<String> extractTokenFromRequest(HttpServletRequest request, String cookieName) {
		// Prefer cookie first
		if (request.getCookies() != null) {
			for (jakarta.servlet.http.Cookie cookie : request.getCookies()) {
				if (cookieName.equals(cookie.getName())) {
					return Optional.ofNullable(cookie.getValue());
				}
			}
		}

		// Fallback to Authorization header
		String header = request.getHeader("Authorization");
		if (header != null && header.startsWith("Bearer ")) {
			return Optional.of(header.substring(7));
		}

		return Optional.empty();
	}

	// ------------------ INTERNAL HELPERS ------------------

	private Claims parseClaims(String token) {
		return Jwts.parserBuilder().setSigningKey(keyProvider.getPublicKey()).build().parseClaimsJws(token).getBody();
	}

	private Optional<Claims> parseClaimsOptional(String token) {
		try {
			return Optional.of(parseClaims(token));
		} catch (JwtException | IllegalArgumentException e) {
			return Optional.empty();
		}
	}

	// ------------------ RECORD ------------------

	public record JwtClaims(String username, Set<String> roles, Date expiration) {
	}
}
