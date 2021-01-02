# Spring_Security
 Repository for studying Spring_Security

---

# 1 스프링 시큐리티 기본 API 

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
인증을 하지 않은 사용자를 단지 user 객체가 null 이라는 단순한 개념이 아닌 
AnonymouAuthenticationToken 객체에  익명사용자의 정보를 저장하고
(사용자명, 권한, 인증여부 등..) 이를 SecuirtyContext 객체에 저장하여 어플리케이션 
전역적으로 사용할 수있도록 도입했을 뿐

즉, 익명사용자일 경우
String user = SecurityContextHolder.getContext().getAuthentication() 하면 
user 에 "anonymousUser" 가 저장되고 이 user 변수는 principal 에 저장이 되며 
principal 은 AnonymousAuthenticationToken 저장이 되고 최종적으로 
AnonymusAuthenticationToken 은 SecurityContext 에 저장이 되는 계층적 구조 
이러한 전반적인 처리를 하는 필터가 AnonymousAuthenticationFilter
```

## 1-9) 동시세션제어/세션 고정보호/ 세션정책

### 동시 세션 제어

![image](https://user-images.githubusercontent.com/40031858/103266956-06cedc00-49f4-11eb-92d2-7645592cde7c.png)

### http.sessionManagement():세션 관리기능이 작동함

```
protected void configure(HttpSecurity http) throws Exception{
    http.sessionManagement()
        .maximumSessions(1) // 최대 허용 가능 세션 수, -1: 무제한 로그인 세션 허용
        .maxSessionsPreventsLogin(true) // 동시 로그인 차단함, false: 기존 세션 만료(default)
        .invalidSessionUrl("/invalid") //세션이 유효하지 않을 때 이동할 페이지
        .expiredUrl("/expired") //세션이 만료된 경우 이동 할 페이지
}
```

### 세션 고정 보호

![image](https://user-images.githubusercontent.com/40031858/103269907-249f3f80-49fa-11eb-8be1-1e1fb765885a.png)

#### http.sessionManagement(): 세션 관리 기능이 작동함
```
protected void configure(HttpSecurity http) throws Exception{
    http.sessionManagement()
        .sessionFixation().changeSessionId()//기본값
        // none,migrateSession, newSession
}
```

### 세션 정책

```
protected void configure(HttpSecurity http) throws Exception{
    http.sessionManagement()
        .sessionCreationPolicy(SessionCreationPolicy.If_Required)
}

SessionCreationPolicy.Always : 스프링 시큐리티가 항상세션생성
SessionCreationPolicy.If_Required : 스프링 시큐리티가 필요시 생성(기본값)
SessionCreationPolicy.Never : 스프링 시큐리티가 생성하지 않지만 이미 존재하면 사용
SessionCreationPolicy.Stateless : 스프링 시큐리티가 생성하지 않고 존재해도 사용하지 않음
```

---

## 1-10) SessionManagementFilter,ConcurrentSessionFilter
### 인증 API- SessionManagementFilter
1. 세션 관리
    - 인증 시 사용자의 세션정보를 등록, 조회, 삭제 등의 세션 이력을 관리
2. 동시적 세션 제어
    - 동일 계정으로 접속이 허용되는 최대 세션수를 제한
3. 세션고정보호
    - 인증 할 때마다 세션 쿠키를 새로 발급하여 공격자의 쿠키 조작을 방지
4. 세션 정책 생성
    - Always,If_Required,Never,Stateless

### 인증 API- ConcurrentSessionFilter
- 매 요청 마다 현재 사용자의 세션 만료 여부 체크
- 세션이 만료로 설정되었을 경우 즉시만료처리
- session.isExpired()==true
    - 로그아웃 처리
    - 즉시 오류페이지 응답("this session has been expired")

![image](https://user-images.githubusercontent.com/40031858/103327417-cb85e900-4a97-11eb-9788-c95283520496.png)

![image](https://user-images.githubusercontent.com/40031858/103327425-d8a2d800-4a97-11eb-8693-737d05c6add5.png)

---

## 1-11) 권한 설정과 표현식
### 인가 API- 권한 설정
- 선언적 방식
    - URL
        - http.antMatchers("/users/**").hasRole("USER")
    - Method
        - @PreAuthorize("hasRole('USER')")
            public void user(){println("user")}
- 동적 방식- DB 연동 프로그래밍
    - URL
    - Method

```
@Override
protected void configure(HttpSecurity http) throws Exception{
    http
        .antMatcher("/shop/**")
        .authorizeRequests()
            .antMatchers("/shop/login","shop/users/**").permitAll()
            .antMatchers("/shop/mypage").hasRole("USER")
            .antMatchers("/shop/admin/pay").access("hasRole('ADMIN')");
            .antMatchers("/shop/admin/**").access("hasRole('ADMIN') or hasRole('SYS')");
            .anyRequest().authenticated()
}
    주의사항- 설정시 구체적인 경로가 먼저오고 그것보다 큰 범위의 경로가 뒤에 오도록 해야함.
```

![image](https://user-images.githubusercontent.com/40031858/103433385-83033280-4c33-11eb-97a6-388751e20a61.png)


## 1-12) 예외 처리 및 요청 캐시 필터

### 인증/인가 API- ExceptionTranslationFilter
- AuthenticationException
    - 인증 예외 처리
    1. AuthenticationEntryPoint 호출
        - 로그인 페이지 이동, 401 오류 코드 전달 등
    2. 인증 예외가 발생하기 전 요청정보 저장
        - RequestCache- 사용자의 이전 요청 정보를 세션에 저장하고 이를 꺼내오는 캐시 메커니즘
        - SavedRequest- 사용자가 요청했던 reqeust파라미터 값들. 그 당시 헤더값들 등이 저장
- AccessDeniedException
    - 인가 예외 처리
        - AccessDeniedHandler 에서 예외 처리하도록 제공

![image](https://user-images.githubusercontent.com/40031858/103450178-e05fb800-4cf5-11eb-8dac-82d477670ee5.png)

### http.exceptionHandling(): 예외처리 기능이 작동
```
protected void configure(HttpSecurity http) throws Exception{
    http.exceptionHandling()
        .authenticationEntryPoint(authenticationEntryPoint()) // 인증 실패 시 처리
        .accessDeniedHandler(accessDeniedHandler())// 인증 실패 시 처리
}
```