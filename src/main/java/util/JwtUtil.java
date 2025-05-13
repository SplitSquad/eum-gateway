package util;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JwtUtil {

    private SecretKey secretKey;

    public JwtUtil(@Value("${jwt.token.secret}") String secret) {
        secretKey = new SecretKeySpec(
                secret.getBytes(StandardCharsets.UTF_8),
                Jwts.SIG.HS256.key().build().getAlgorithm()
        );
    }

    public Long getUserid(String token) {
        return Jwts.parser().verifyWith(secretKey).build()
                .parseClaimsJws(token)
                .getPayload()
                .get("userId",  Long.class);
    }

    public String getRole(String token) {
        return Jwts.parser().verifyWith(secretKey).build()
                .parseClaimsJws(token).getPayload().get("role", String.class);
    }

    public String getEmail(String token) {
        return Jwts.parser().verifyWith(secretKey).build()
                .parseClaimsJws(token).getPayload().get("email", String.class);
    }

    public Boolean isExpired(String token) {
        try {
            Date exp = Jwts.parser().verifyWith(secretKey).build()
                    .parseClaimsJws(token)
                    .getPayload()
                    .getExpiration();
            return exp.before(new Date());
        } catch (ExpiredJwtException e) {
            return true;
        }
    }
}