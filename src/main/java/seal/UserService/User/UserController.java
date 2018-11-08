package seal.UserService.User;

import java.util.List;
import java.util.Map;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@CrossOrigin(origins = "http://localhost:8080", maxAge = 3600)
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private TokenAuthenticationService tokenAuthenticationService;

    @GetMapping("/users")
    public ResponseEntity<List<User>> getAllUser() {
        List<User> user = userService.getAllUsers();
        return new ResponseEntity<List<User>>(user,HttpStatus.OK);
    }

    @PostMapping(path = "/user/signin")
    public ResponseEntity<Boolean> signInByStudentId(@Valid @RequestBody Map<String, String> user_input, HttpServletResponse response) {
        Long userId = Long.parseLong(user_input.get("id").toString());
        String password = user_input.get("password").toString();

        User user = userService.getUserById(userId);

        if(user != null) {
            String userPassword = user.getPassword();
            if(userPassword.equals(password)) {
                String token = tokenAuthenticationService.createTokenUser(user);
                response.addCookie(new Cookie("cookie_token", token));
                response.addHeader("token", token);
                return new ResponseEntity<Boolean>(true, HttpStatus.OK);
            }
        }
        return new ResponseEntity<Boolean>(false, HttpStatus.OK);
    }
}