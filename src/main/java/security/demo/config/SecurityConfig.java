package security.demo.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    UserDetailsService userDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
//        http
//                .authorizeRequests()
//                .anyRequest().authenticated(); //요청에 대한 보안검사 시작 (인가정책)
//        http.formLogin();
////        http
////            .formLogin() //form login 방식의 인증
////            //.loginPage("/loginPage")
////            .defaultSuccessUrl("/")
////            .failureUrl("/login")
////            .usernameParameter("userId")
////            .passwordParameter("passwd")
////            .loginProcessingUrl("/login_proc")
////            .successHandler((request, response, authentication) -> {
////                System.out.println("authentication :"+authentication.getName());
////                response.sendRedirect("/");
////            }).failureHandler((request, response, exception) -> {
////                System.out.println("exception :"+ exception.getMessage());
////                response.sendRedirect("/login");
////            })
////                .permitAll(); //loginPage에 접근하는 클라이언트들은 인증받지않아도 가능
//
//        /*==========logout================ */
//
//        http
//                .logout()
//                .logoutUrl("/logout")
//                .logoutSuccessUrl("/login")
//                .addLogoutHandler((request, response, authentication) -> {
//                    HttpSession session = request.getSession();
//                    session.invalidate();
//                })
//                .logoutSuccessHandler((request, response, authentication) -> {
//                    response.sendRedirect("/login");
//                })
//               .and()
//                .rememberMe()
//                .rememberMeParameter("remember")
//                .tokenValiditySeconds(3600)
//                .userDetailsService(userDetailsService);
            http.authorizeRequests()
                    .anyRequest().authenticated();
            http
                    .formLogin();
            http
                    .rememberMe()
                    .userDetailsService(userDetailsService);
    }
}
