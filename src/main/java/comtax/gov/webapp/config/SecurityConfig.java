package comtax.gov.webapp.config;

import comtax.gov.webapp.filter.JwtAuthenticationFilter;
import comtax.gov.webapp.filter.LoginRateLimitFilter;
import comtax.gov.webapp.security.CustomAccessDeniedHandler;
import comtax.gov.webapp.security.UnauthorizedEntryPoint;
import comtax.gov.webapp.service.AuthServiceDetails;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.StaticHeadersWriter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.List;

@Configuration
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final LoginRateLimitFilter loginRateLimitFilter;
    private final UnauthorizedEntryPoint unauthorizedEntryPoint;
    private final CustomAccessDeniedHandler accessDeniedHandler;
    private final AuthServiceDetails authServiceDetails;

    /**
     * Main Security Filter Chain
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        log.info("Configuring SecurityFilterChain");

        http.cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .csrf(csrf -> csrf.disable())
            .exceptionHandling(ex -> ex
                    .authenticationEntryPoint(unauthorizedEntryPoint)
                    .accessDeniedHandler(accessDeniedHandler))
            .headers(headers -> {
                headers.httpStrictTransportSecurity(hsts -> hsts.includeSubDomains(true).maxAgeInSeconds(31536000));
                headers.frameOptions(frame -> frame.deny());
                headers.referrerPolicy(ref -> ref.policy(
                        org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER_WHEN_DOWNGRADE));
                headers.addHeaderWriter(new StaticHeadersWriter("X-Content-Type-Options", "nosniff"));
                headers.addHeaderWriter(new StaticHeadersWriter("Permissions-Policy", "geolocation=(), microphone=(), camera=()"));
                headers.addHeaderWriter(new StaticHeadersWriter("Content-Security-Policy",
                        "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; frame-ancestors 'none';"));
            })
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                    // Allow preflight requests
                    .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                    // Public endpoints
                    .requestMatchers("/auth/**").permitAll()
                    .requestMatchers(HttpMethod.GET, "/swagger-ui/**", "/v3/api-docs/**").permitAll()
                    .requestMatchers("/actuator/**").permitAll()
                    // All other endpoints require authentication
                    .anyRequest().authenticated())
            // Add custom filters before username/password filter
            .addFilterBefore(loginRateLimitFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * CORS Configuration Source
     */
    @Bean
    public UrlBasedCorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        configuration.setAllowedOrigins(List.of(
                "http://10.153.45.169:5174",
                "http://10.153.43.8:8084",
                "http://localhost:5173",
                "http://localhost:5174"
        ));
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(true);
        configuration.setExposedHeaders(List.of("Set-Cookie", "Authorization"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }

    /**
     * Ensure CORS filter runs before other filters
     */
    @Bean
    public CorsFilter corsFilter() {
        return new CorsFilter(corsConfigurationSource());
    }

    /**
     * Authentication Manager Bean
     */
    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder authBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        authBuilder.userDetailsService(authServiceDetails)
                   .passwordEncoder(passwordEncoder());
        return authBuilder.build();
    }

    /**
     * Password Encoder Bean
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
