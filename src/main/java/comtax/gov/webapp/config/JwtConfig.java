package comtax.gov.webapp.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Configuration
public class JwtConfig {

	@Value("${jwt.private-key-path}")
	private Resource privateKeyResource;

	@Value("${jwt.public-key-path}")
	private Resource publicKeyResource;

	@Bean
	public KeyPair keyPair() {
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");

			PrivateKey privateKey = loadPrivateKey(keyFactory, privateKeyResource);
			PublicKey publicKey = loadPublicKey(keyFactory, publicKeyResource);

			return new KeyPair(publicKey, privateKey);
		} catch (Exception ex) {
			throw new IllegalStateException("Failed to load JWT keys", ex);
		}
	}

	private PrivateKey loadPrivateKey(KeyFactory keyFactory, Resource resource) throws Exception {
		String key = readPem(resource)
				.replaceAll("-----BEGIN (?:RSA )?PRIVATE KEY-----|-----END (?:RSA )?PRIVATE KEY-----", "")
				.replaceAll("\\s+", "");
		byte[] decoded = Base64.getDecoder().decode(key);
		return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decoded));
	}

	private PublicKey loadPublicKey(KeyFactory keyFactory, Resource resource) throws Exception {
		String key = readPem(resource).replaceAll("-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----", "")
				.replaceAll("\\s+", "");
		byte[] decoded = Base64.getDecoder().decode(key);
		return keyFactory.generatePublic(new X509EncodedKeySpec(decoded));
	}

	private String readPem(Resource resource) throws Exception {
		try (InputStream is = resource.getInputStream()) {
			return new String(is.readAllBytes());
		}
	}
}
