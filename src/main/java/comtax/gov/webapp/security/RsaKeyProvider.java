package comtax.gov.webapp.security;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;
import jakarta.annotation.PostConstruct;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Component
@Slf4j
@Getter
public class RsaKeyProvider {

	private PrivateKey privateKey;
	private PublicKey publicKey;

	@Value("${jwt.private-key-path}")
	private Resource privateKeyResource;

	@Value("${jwt.public-key-path}")
	private Resource publicKeyResource;

	@PostConstruct
	public void init() {
		try {
			this.privateKey = loadPrivateKey(privateKeyResource);
			this.publicKey = loadPublicKey(publicKeyResource);
			log.info("RSA keys loaded successfully");
		} catch (Exception e) {
			log.error("Failed to load RSA keys", e);
			throw new IllegalStateException("Cannot initialize RSA keys", e);
		}
	}

	private PrivateKey loadPrivateKey(Resource resource) throws Exception {
		String keyContent = readResource(resource).replaceAll("-----\\w+ PRIVATE KEY-----", "").replaceAll("\\s", "");
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(keyContent));
		return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
	}

	private PublicKey loadPublicKey(Resource resource) throws Exception {
		String keyContent = readResource(resource).replaceAll("-----\\w+ PUBLIC KEY-----", "").replaceAll("\\s", "");
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(keyContent));
		return KeyFactory.getInstance("RSA").generatePublic(keySpec);
	}

	private String readResource(Resource resource) throws IOException {
		try (var is = resource.getInputStream()) {
			return new String(is.readAllBytes(), StandardCharsets.UTF_8);
		}
	}
}
