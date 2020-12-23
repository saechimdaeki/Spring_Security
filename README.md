# Spring_Security
 Repository for studying Spring_Security

## 1-1). 인증 api - 사용자 정의 보안 기능 구현

![image](https://user-images.githubusercontent.com/40031858/102893725-6afa1900-44a5-11eb-8af2-f552d32a1c96.png)

```
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter{

    @Override
    protected void configure(HttpSecurity http) throws Exception{
        http
            .authorizeRequests()
            .anyRequest().authenticated()
        .and()
            .formLogin();
    }

}
```

## 1-2). 인증 API - HTTP Basic인증, BasicAuthenticationFilter

![image](https://user-images.githubusercontent.com/40031858/102970155-59af1c00-453a-11eb-9921-d33e526e84f8.png)


```
protected void configure(HttpSecurity http) throws Exception{
    http.httpBasic();
}
```

## 1-3) 인증 API - Form 인증
#### http.formLogin() : Form 로그인 인증 기능이 작동함
```
protected void configure(HttpSecurity http) throws Exception{
    http.formLogin()
    .loginPage("/login.html") //사용자 정의 로그인 페이지
    .defaultSuccessUrl("/home") // 로그인 성공 후 이동 페이지
    .failureUrl("/login.html?error=true") // 로그인 실패 후 이동 페이지
    .usernameParameter("username") // 아이디 파라미터명 설정
    .passwordParameter("password") // 패스워드 파라미터명 설정
    .loginProcessingUrl("/login") // 로그인 Form Action Url
    .successHandler(loginSuccessHandler()) // 로그인 성공 후 핸들러
    .failureHandler(loginFailureHandler()) // 로긍니 실패 후 핸들러
}
```

## 1-4) 인증 API - UsernamePasswordAuthenticationFilter

#### Login Form 인증

![image](https://user-images.githubusercontent.com/40031858/102995477-77917680-4564-11eb-9e2f-9d071535b904.png)

#### UsernamePasswordAuthenticationFilter

![image](https://user-images.githubusercontent.com/40031858/102995608-c9d29780-4564-11eb-8e0f-9f190ebbe734.png)

## 1-5) 인증 API- Logout,LogoutFilter

#### 로그아웃 과정
![image](https://user-images.githubusercontent.com/40031858/102997257-fb009700-4567-11eb-86d0-2c1e4d95a325.png)

### http.logout(): 로그아웃 기능이 작동
```
protected void configure(HttpSecurity http) throws Exception{
    http.logout()   //로그아웃 처리
        .logoutUrl("/logout")   //로그아웃 처리 URL
        .logoutSuccessUrl("/login") //로그아웃 성공후 이동페이지
        .deleteCookies("JSESSIONID", "remember-me") //로그아웃 후 쿠키 삭제
        .addLogoutHandler(logoutHandler())  //로그아웃 핸들러
        .logoutSuccessHandler(logoutSuccessHandler())   // 로그아웃 성공 후 핸들러
}
```

![image](https://user-images.githubusercontent.com/40031858/102997396-6185b500-4568-11eb-8fa0-261758c2bb3d.png)

LogoutFilter

![image](https://user-images.githubusercontent.com/40031858/102997435-7c582980-4568-11eb-929d-1b106c5c782a.png)
