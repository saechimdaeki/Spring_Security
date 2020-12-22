# Spring_Security
 Repository for studying Spring_Security

# 1. 인증 api - 사용자 정의 보안 기능 구현

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