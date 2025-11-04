package comtax.gov.webapp.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import comtax.gov.webapp.entities.UserEntity;
import comtax.gov.webapp.repo.UserRepository;
import org.springframework.data.redis.core.RedisTemplate;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceDetails implements UserDetailsService {

    private final UserRepository userRepository;
    private final RedisTemplate<String, Object> redisTemplate;

    private static final String USER_CACHE_PREFIX = "user_auth:";
    private static final long CACHE_TTL_MINUTES = 10;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        String redisKey = USER_CACHE_PREFIX + username;

        try {            
            UserDetails cachedUser = (UserDetails) redisTemplate.opsForValue().get(redisKey);
            if (cachedUser != null) {
                log.info("Loaded user '{}' from Redis cache", username);
                return cachedUser;
            }
        } catch (Exception e) {
            log.warn("Failed to read user '{}' from Redis cache: {}", username, e.getMessage());
        }

        // Fallback to DB lookup
        log.info("Fetching user '{}' from database", username);
        Optional<UserEntity> optionalUser = userRepository.findByUserCode(username);

        UserEntity userEntity = optionalUser
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        //  Wrap entity in CustomUserDetails (your custom implementation)
        CustomUserDetails userDetails = new CustomUserDetails(userEntity);

        // Store in Redis for future use
        try {
            redisTemplate.opsForValue().set(redisKey, userDetails, CACHE_TTL_MINUTES, TimeUnit.MINUTES);
            log.info(" Cached user '{}' in Redis for {} minutes", username, CACHE_TTL_MINUTES);
        } catch (Exception e) {
            log.warn("Failed to cache user '{}' in Redis: {}", username, e.getMessage());
        }

        return userDetails;
    }

    /**
     * 🗑️ Remove user from Redis cache (on password change, logout, etc.)
     */
    public void evictUserCache(String username) {
        try {
            redisTemplate.delete(USER_CACHE_PREFIX + username);
            log.info("Evicted cached user '{}' from Redis", username);
        } catch (Exception e) {
            log.error(" Failed to evict user '{}' cache: {}", username, e.getMessage());
        }
    }
}


//import java.util.concurrent.TimeUnit;
//
//import org.springframework.data.redis.core.RedisTemplate;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.core.userdetails.UsernameNotFoundException;
//import org.springframework.stereotype.Service;
//import comtax.gov.webapp.entities.UserEntity;
//import comtax.gov.webapp.repo.UserRepository;
//import lombok.RequiredArgsConstructor;
//import lombok.extern.slf4j.Slf4j;
//
//@Service
//@RequiredArgsConstructor
//@Slf4j



//public class AuthServiceDetails implements UserDetailsService {
//	
//	private final UserRepository userRepository;
//    @Override
//    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//        log.info("Fetching user details for username: {}", username);
//
//        UserEntity user = userRepository.findByUserCode(username)
//                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
//
//        return new CustomUserDetails(user);
//    }
//    
//   
//
//}
