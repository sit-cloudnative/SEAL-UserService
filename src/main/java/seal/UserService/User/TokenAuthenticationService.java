package seal.UserService.User;

import java.security.Key;
import java.util.Date;

import javax.servlet.http.HttpServletRequest;

import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

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

    public String getAuthenticationToken(HttpServletRequest request){
        String token = request.getHeader("token");

        if(token == null) {
            return null;
        }

        String studentId = Jwts.parser()
                .setSigningKey(SECRET_KEY)
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
        
        return studentId;
    }

}