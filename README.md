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

## 1-13) Form 인증 - CSRF,CsrfFilter

### CSRF(사이트 간 요청 위조)

![image](https://user-images.githubusercontent.com/40031858/103474244-48d99280-4de5-11eb-8a88-d84dd2f11bf0.png)

### CsrfFilter
- 모든 요청에 랜덤하게 생성된 토큰을 HTTP 파라미터로 요구
- 요청 시 전달되는 토큰값과 서버에 저장된 실제 값과 비교후 만약 일치하지 않으면 요청은실패
- Client
    - < input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}" />
    - HTTP 메소드: PATCH, POST, PUT, DELETE
- Spring Security
    - http.csrf(): 기본 활성화되어 있음
    - http.csrf().disabled(): 비활성화

------

# 2.스프링 시큐리티 주요 아키텍쳐 이해
## 2-1) 위임 필터 및 필터 빈 초기화 

### DelegatingFilterProxy

![image](https://user-images.githubusercontent.com/40031858/103987609-1d351e80-51d0-11eb-8450-ef2a5a2d094c.png)

### FilterChainProxy
1. springSecurityFilterChain의 이름으로 생성되는 필터 빈
2. DelegatingFilterProxy 으로 부터 요청을 위임 받고 실제 보안 처리
3. 스프링 시큐리티 초기화 시 생성되는 필터들을 관리하고 제어
    - 스프링 시큐리티가 기본적으로 생성하는 필터
    - 설정 클래스에서 API 추가 시 생성되는 필터
4. 사용자의 요청을 필터 순서대로 호출하여 전달
5. 사용자정의 필터를 생성해서 기존의 필터 전.후로 추가 가능
    - 필터의 순서를 잘 정의
6. 마지막 필터까지 인증 및 인가 예외가 발생하지 않으면 보안 통과

![image](https://user-images.githubusercontent.com/40031858/103987993-b3694480-51d0-11eb-9693-b7b6a971005e.png)

---

## 2-2 ) 필터 초기화와 다중 보안 설정
### 필터 초기화와 다중 설정 클래스 

![image](https://user-images.githubusercontent.com/40031858/104301570-26ddbf80-550b-11eb-9951-aec2e018b09c.png)

![image](https://user-images.githubusercontent.com/40031858/104301610-34934500-550b-11eb-90c7-17421c5ac454.png)

### WebSecurity, HttpSecurity, WebSecurityConfigurerAdapter

![image](https://user-images.githubusercontent.com/40031858/104301660-3f4dda00-550b-11eb-8480-a63b130bdaf7.png)


---

## 2-3 Authentication

### Authentication
- 당신이 누구인지 증명하는 것
    - 사용자의 인증정보를 저장하는 토큰 개념
    - 인증 시 id와 password를 담고 인증 검증을 위해 전달되어 사용된다
    - 인증 후 최종 결과(user객체, 권한정보를)담고 SecurityContext에 저장되어 전역적으로 참조 가능
    - Authentication authentication =SecurityContextHolder.get(Context().getAuthentication())
- 구조
    1. principal: 사용자 아이디 혹은 User객체를 저장
    2. credentials: 사용자 비밀번호
    3. authorities: 인증된 사용자의 권한목록
    4. details: 인증 부가정보
    5. Authenticated: 인증 여부

![image](https://user-images.githubusercontent.com/40031858/105342126-4d92a900-5c23-11eb-879d-a6f4cc326f17.png)

---

## 2-4 SecurityContextHolder,SecurityContext

### SecurityContext
- Authentication 객체가 저장되는 보관소로 필요 시 언제든지 Authentication 객체를 꺼내어 쓸 수 있도록 제공되는 클래스
- ThreadLocal에 저장되어 아무 곳에서나 참조가 가능하도록 설계함
- 인증이 완료되면 HttpSession에 저장되어 어플리케이션 전반에 걸쳐 전역적인 참조가 가능하다
### SecurityContextHolder
- SecurityContext 객체 저장 방식
    - MODE_THREADLOCAL: 스레드당 SecurityContext 객체를 할당, 기본값
    - MODE_INHERITABLETHREADLOCAL : 메인 스레드와 자식 스레드에 관하여 동일한 SecurityContext 를 유지
    - MODE_GLOBAL :  응용 프로그램에서 단 하나의 SecurityContext를 저장한다
- SecurityContextHolder.clearContext():SecurityContext 기존정보 초기화

- Authentication authentication= SecurityContextHolder.getContext().getAuthentication()

![image](https://user-images.githubusercontent.com/40031858/105619141-20b4e080-5e33-11eb-842b-aa39c7e9ce3e.png)

---

## 2-5 - SecurityContextPersistenceFilter

### 익명 사용자
- 새로운 SecurityContext 객체를 생성하여 SecurityContextHolder에 저장
- AnonymousAuthenticationFilter 에서 AnonymousAuthenticationToken 객체를 SecurityContext에 저장

### 인증 시
- 새로운 SecurityContext 객체를 생성하여 SecurityContextHolder에 저장
- UsernamePasswordAuthenticationFilter에서 인증 성공후 SecurityContext에 UsernamePasswordAuthentication 객체를 SecurityConext에 저장
- 인증이 최종 완료되면 Session에SecurityContext를 저장

### 인증 후
- Session에서 SecurityContext 꺼내어 SecurityContextHolder에서 저장
- SecurityContext안에 Authentication 객체가 존재하면 계속 인증을 유지한다

### 최종 응답 시 공통
- SecurityContextHolder.cleanContext()

![image](https://user-images.githubusercontent.com/40031858/105697047-64990a00-5f47-11eb-8497-c13d9b2b2ac0.png)

![image](https://user-images.githubusercontent.com/40031858/105697064-6ebb0880-5f47-11eb-8360-86e0dff8228d.png)

![image](https://user-images.githubusercontent.com/40031858/105697103-79759d80-5f47-11eb-9e82-8360d2bad48e.png)

---

## 2-6 Authentication Flow

![image](https://user-images.githubusercontent.com/40031858/106146896-94037d00-61ba-11eb-9557-d6fc9151810d.png)

---

## 2-7 AuthenticationManager

![image](https://user-images.githubusercontent.com/40031858/106149729-f01bd080-61bd-11eb-81ed-a59ae8844cf1.png)

---

## 2-8 인증처리자 AuthenticationProvider

![image](https://user-images.githubusercontent.com/40031858/106345949-dc27ba00-62f6-11eb-902a-e0a10d18d6b3.png)

---

## 2-9 Authorization, FilterSecurityInterceptor 

![image](https://user-images.githubusercontent.com/40031858/106346448-90770f80-62fa-11eb-9cff-be21ff0c0947.png)

![image](https://user-images.githubusercontent.com/40031858/106346456-aedd0b00-62fa-11eb-8dee-f4909fb5fcab.png)

### FilterSecurityInterceptor
- 마지막에 위치한 필터로써 인증된 사용자에 대하여 특정 요청의 승인/거부 여부를 최종적으로 결정
- 인증객체 없이 보호차원에 접근을 시도할 경우 AuthenticationException을 발생
- 인증 후 자원에 접근 가능한 권한이 존재하지 않을 경우 AccessDeniedException을 발생
- 권한 제어 방식 중 HTTP 자원의 보안을 처리하는 필터
- 권한 처리를 AccessDecisionManager에게 맡김

![image](https://user-images.githubusercontent.com/40031858/106346505-0aa79400-62fb-11eb-8da7-421e74880c2e.png)

![image](https://user-images.githubusercontent.com/40031858/106346513-16935600-62fb-11eb-9708-15fc7b371f99.png)

---

## 2-10 AccessDecisionManager, AccessDecisionVoter

### AccessDecisionManager
- 인증 정보, 요청정보, 권한정보를 이용해 사용자의 자원접근을 허용할것인지 거부할것인지 최종결정하는 주체
- 여러개의 Voter들을 가질 수 있으며 Voter들로부터 접근허용,거부,보류에 해당하는 각각의값을 리턴받고 판단 및 결정
- 최종 접근 거부 시 예외 발생

![image](https://user-images.githubusercontent.com/40031858/106372853-4bfd7980-63b7-11eb-82e3-491c527c1288.png)

### AccessDecisionVoter
- 판단을 심사하는것(위원)
- Voter가 권한 부여 과정에서 판단하는 자료
    - Autehntication-인증 정보(user)
    - FilterInvocation - 요청 정보(antMatcher("/user"))
    - ConfigAttributes - 권한 정보(hasRole("USER"))
- 결정 방식
    - ACCESS_GRANTED: 접근허용(1)
    - ACCESS_DENIED: 접근 거부(0)
    - ACCESS_ABSTRAIN:접근 보류(-1)
        - Voter가 해당 타입의 요청에 대해 결정을 내릴 수 없는 경우

![image](https://user-images.githubusercontent.com/40031858/106372876-967ef600-63b7-11eb-9afc-39c31789488b.png)


![image](https://user-images.githubusercontent.com/40031858/106373179-4b1a1700-63ba-11eb-8014-66503ff43807.png)

---

## 2-11 스프링 시큐리티 필터 및 아키텍처 정리

![image](https://user-images.githubusercontent.com/40031858/106373190-608f4100-63ba-11eb-92cb-ac6a646c0c40.png)


----

----

----

## Form 인증 - PasswordEncoder
- 비밀번호를 안전하게 암호화 하도록 제공
- Spring Security5.0 이전에는 기본 PasswordEncoder가 평문을 지원하는 NoOpPasswordEncoder(현재는 Deprecated)
- 생성
    - PasswordEncoder passwordEncoder=PasswordEncoderFactories.createDelegatingPasswordEncoder()
    - 여러개의 PasswordEncoder 유형을 선언한 뒤, 상황에 맞게 선택해서 사용할 수 있도록 지원하는 Encoder이다.
- 암호화 포맷: {id}encodedPassword
    - 기본 포맷은 Bcrpt
    - 알고리즘 종류 :bcrpty,noop,pbkdf2,scrypt,sha256t
    - encode(passowrd)
        - 패스워드 암호화
    - matches(rawPassword,encodedPassword)
        - 패스워드 비교