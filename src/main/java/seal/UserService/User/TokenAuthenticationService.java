package seal.UserService.User;

import java.security.Key;
import java.util.Date;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import static java.util.Collections.emptyList;

@Service
public class TokenAuthenticationService {

    public static long EXPIRATION_TIME = 1000 * 30; // 30 seconds timeout
    static Key SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS256);

    public String createTokenUser(User user) {
        Date now = new Date();
        Claims claims = Jwts.claims().setSubject(""+user.getId());

        String token = Jwts.builder()
        .setClaims(claims)
        .setIssuedAt(now)
        .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
        .signWith(SECRET_KEY)
        .compact();
        return token;
    }

    public static Authentication getAuthentication(HttpServletRequest request) {
        String token = request.getHeader("Authorization");
        if (token != null) {
            // parse the token.
            String user = Jwts.parser() // แปลง token ที่รับมาจาก request ได้ค่า user.getId() ที่เราเก็บไว้
                    .setSigningKey(SECRET_KEY)
                    .parseClaimsJws(token.replace("Bearer", ""))
                    .getBody()
                    .getSubject();

            return user != null ?
                    new UsernamePasswordAuthenticationToken(user, null, emptyList()) : // ถ้า user ไม่ใช่ null ให้ส่งค่า user ว่าผ่านได้
                    null;
        }
        return null;
    }

}