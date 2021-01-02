package security.demo.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("user").password("{noop}1234").roles("USER");
        auth.inMemoryAuthentication().withUser("sys").password("{noop}1234").roles("SYS");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}1234").roles("ADMIN","SYS","USER");

    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/login").permitAll()
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/admin/pay").hasRole("ADMIN")
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                .anyRequest().authenticated();
        http
                .formLogin()
                .successHandler((request, response, authentication) -> {
                    RequestCache requestCache=new HttpSessionRequestCache();
                    SavedRequest savedRequest=requestCache.getRequest(request,response);
                    String redirectUrl = savedRequest.getRedirectUrl();
                    response.sendRedirect(redirectUrl); //인증 성공시 바로 세션에 저장되어있던 url로 이동
                    //System.out.println(redirectUrl);
                });
        http
                .exceptionHandling()
//                .authenticationEntryPoint((request, response, authException) -> {
//                    response.sendRedirect("/login");
//                })
                .accessDeniedHandler((request, response, accessDeniedException) -> {
                    response.sendRedirect("/denied");
                });

    }
}
