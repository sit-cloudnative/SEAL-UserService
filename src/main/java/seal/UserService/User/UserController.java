package seal.UserService.User;

import java.util.Date;
import java.util.HashMap;
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
@CrossOrigin(origins = "*", maxAge = 3600)
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private TokenAuthenticationService tokenAuthenticationService;

    @Autowired
    private UserRepository userRepository;

    @GetMapping("/users")
    public ResponseEntity<List<User>> getAllUser() {
        List<User> user = userService.getAllUsers();
        return new ResponseEntity<List<User>>(user, HttpStatus.OK);
    }

    @PostMapping(path = "/user/login")
    public ResponseEntity<String> signInByStudentId(@RequestBody Map<String, String> user_input, HttpServletResponse response) {
        Long userId = Long.parseLong(user_input.get("id").toString());
        String password = user_input.get("password").toString();
//        User son = new User();
//        son.setCreated_at(new Date());
//        son.setDepartment("Information Technology");
//        son.setFirstname("Supakorn");
//        son.setLastname("Trakumaiphol");
//        son.setPassword("wdrdres3qew5ts21");
//        son.setId(59130500097l);
//        userRepository.save(son);
        User user = userService.getUserById(userId);
        HashMap<String, Object> responseData = new HashMap();

        if (user != null) {
            String userPassword = user.getPassword();
            if (userPassword.equals(password)) {
                String token = tokenAuthenticationService.createTokenUser(user);
                response.addCookie(new Cookie("cookie_token", token));
                response.addHeader("token", token);
                System.out.println(response.getHeaderNames());
                responseData.put("status", true);
                responseData.put("jwt", token);
                return new ResponseEntity<String>("wtf", HttpStatus.OK);
            }
        }
        return new ResponseEntity<String>("fail to login", HttpStatus.OK);
    }
}
