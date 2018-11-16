package seal.UserService.Filter;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class FilterConfig extends WebSecurityConfigurerAdapter {

    @Override // ส่วนของ กำหนด filter 
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable().authorizeRequests()
            .antMatchers("/").permitAll() // ให้ ทุกหน้าที่ '/' ผ่านได้เลย โดยไม่ต้อง login 
            .antMatchers(HttpMethod.POST, "/user/login").permitAll() // ให้ '/user/login' ที่เป็น post ผ่านได้
            .anyRequest().authenticated()
            .and()
            .addFilterBefore(
                    new JWTGenericFilterBean(), // เรียกใช้ JWTGenericFilterBean 
                    UsernamePasswordAuthenticationFilter.class
            );
    }
}