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


## 1-6) 인증 API- Remember Me 인증

### 인증 API-Remember ME 인증
1. 세션이 만료되고 웹 브라우저가 종료된 후에도 어플리케이션이 사용자를 기억하는 기능
2. Remember-Me 쿠키에 대한 Http요청을 확인한 후 토큰 기반인증을 사용해 유효성을 검사하고 토큰이 검증되면 사용자는 로그인 된다.
3. 사용자 라이프 사이클 
    - 인증성공(RememberMe쿠키설정)
    - 인증실패(쿠키가 존재하면 쿠키 무효화)
    - 로그아웃(쿠키가 존재하면 쿠키 무효화)

#### http.rememberMe():rememberMe 기능이 작동함
```
protected void configure(HttpSecurity http) throws Exception{
    http.rememberMe()
        .rememberMeParameter("remember") // 기본 파라미터 명은 remember-me
        .tokenValiditySeconds(3600) // Default는 14일
        .alwaysRemember(true) //리멤버 미 기능이 활성화 되지 않아도 항상 실행
        .userDetailsService(userDetailsService)
}
```

## 1-7) Remember Me 인증 필터 : RememberMeAuthenticationFilter

![image](https://user-images.githubusercontent.com/40031858/103162882-c9265380-4839-11eb-8a90-414fee3d81b2.png)

![image](https://user-images.githubusercontent.com/40031858/103162884-d6dbd900-4839-11eb-8e89-127d34ab3cea.png)

## 1-8) 익명사용자 인증 필터 : AnonymousAuthenticationFilter

![image](https://user-images.githubusercontent.com/40031858/103163114-0e985000-483d-11eb-8cbc-20f98a8c22f3.png)

```
인증을 하지 않은 사용자를 단지 user 객체가 null 이라는 단순한 개념이 아닌 AnonymouAuthenticationToken 객체에  익명사용자의 정보를 저장하고(사용자명, 권한, 인증여부 등..) 이를 SecuirtyContext 객체에 저장하여 어플리케이션 전역적으로 사용할 수있도록 도입했을 뿐

즉, 익명사용자일 경우
String user = SecurityContextHolder.getContext().getAuthentication() 하면 user 에 "anonymousUser" 가 저장되고 이 user 변수는 principal 에 저장이 되며 principal 은 AnonymousAuthenticationToken 저장이 되고 최종적으로 AnonymusAuthenticationToken 은 SecurityContext 에 저장이 되는 계층적 구조 
이러한 전반적인 처리를 하는 필터가 AnonymousAuthenticationFilter
```