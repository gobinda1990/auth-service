package comtax.gov.webapp.service;

import comtax.gov.webapp.entities.Impact2User;
import comtax.gov.webapp.repo.AuthRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
//import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

/**
 * Service to load user details for authentication.
 * Uses Redis caching for performance and database fallback if cache misses.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceDetails implements UserDetailsService {

    private final AuthRepository userRepository;
//    private final RedisTemplate<String, Object> redisTemplate;

    private static final String USER_CACHE_PREFIX = "user_auth:";
    private static final long CACHE_TTL_MINUTES = 30;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        String redisKey = USER_CACHE_PREFIX + username;

        //  Try loading from Redis cache
//        try {
//            UserDetails cachedUser = (UserDetails) redisTemplate.opsForValue().get(redisKey);
//            if (cachedUser != null) {
//                log.info("Loaded user '{}' from Redis cache", username);
//                return cachedUser;
//            }
//        } catch (Exception e) {
//            log.warn("Failed to read user '{}' from Redis: {}", username, e.getMessage());
//        }

        //  Fallback: Fetch from database
        log.info(" Fetching user '{}' from database", username);
        Optional<Impact2User> optionalUser = userRepository.findByHrmsCode(username);

        Impact2User userEntity = optionalUser
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        //  Wrap DB entity inside CustomUserDetails
        CustomUserDetails userDetails = new CustomUserDetails(userEntity);

        //  Cache in Redis for future requests
//        try {
//            redisTemplate.opsForValue().set(redisKey, userDetails, CACHE_TTL_MINUTES, TimeUnit.MINUTES);
//            log.info(" Cached user '{}' in Redis for {} minutes", username, CACHE_TTL_MINUTES);
//        } catch (Exception e) {
//            log.warn("Failed to cache user '{}' in Redis: {}", username, e.getMessage());
//        }

        return userDetails;
    }

    /**
     * 🗑️ Evict user from Redis cache (e.g., after password change or logout)
     */
    public void evictUserCache(String username) {
        try {
//            redisTemplate.delete(USER_CACHE_PREFIX + username);
            log.info(" Evicted cached user '{}' from Redis", username);
        } catch (Exception e) {
            log.error(" Failed to evict user '{}' cache: {}", username, e.getMessage());
        }
    }
}



