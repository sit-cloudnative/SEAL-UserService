package seal.UserService.User;

import java.security.Key;
import java.util.Date;

import org.springframework.stereotype.Service;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@Service
public class TokenAuthenticationService {

    public static long EXPIRATION_TIME = 1000 * 30; // 30 seconds timeout
    static Key SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS256);

    public String createTokenUser(User user) {
        String token = Jwts.builder()
        .setSubject("UserService")
        .claim("id", user.getId())
        .claim("firstname", user.getFirstname())
        .claim("image", user.getImage())
        .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
        .signWith(SECRET_KEY).compact();
        return token;
    }

}