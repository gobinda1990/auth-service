package comtax.gov.webapp.controller;


import com.nimbusds.jose.jwk.RSAKey;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.security.KeyPair;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@RestController
@RequestMapping("/auth")
@Slf4j
public class JwksController {

    private final KeyPair keyPair;
    private RSAKey jwk;

    @Value("${jwt.key-id:auth-server-key}")
    private String keyId;

    public JwksController(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    @PostConstruct
    public void init() {
        log.info("Initializing JWKS with keyId");
        jwk = new RSAKey.Builder((java.security.interfaces.RSAPublicKey) keyPair.getPublic())
                .keyID(keyId)
                .build();
    }

    @GetMapping("/.well-known/jwks.json")
    public ResponseEntity<Map<String, Object>> jwks() {
        Map<String, Object> response = Map.of("keys", new Object[]{jwk.toPublicJWK().toJSONObject()});
        return ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(24, TimeUnit.HOURS).cachePublic())
                .body(response);
    }
}
