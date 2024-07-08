package sample.springjwt.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import sample.springjwt.jwt.LoginFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    //특정한 메서드들을 빈으로 등록해서 시큐리티 설정을 할 수 있다.
    //인가 작업, CSRF, 로그인 방식 설정

    //authenticationManager 의 매개변수에 넣기 위해
    private final AuthenticationConfiguration authenticationManager;

    //시큐리티를 통해서 회원 정보 저장, 회원가입, 검증할 때는 비밀번호를 해쉬로 암호화시켜서 검증하고 진행한다.
    //Bcrypt 를 사용
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {

        return new BCryptPasswordEncoder();
    }

    //filter 등록 시 LoginFilter 생성자에 빈 주입을 위해 생성
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception{

        return configuration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        //csrf disable -> 세션방식에서는 세션이 항상 고정되기 때문에 csrf 공격을 필수적으로 방어.
        //JWT 방식에서는 세션을 stateless한 상태로 관리하기 때문에, csrf 공격을 방어하지 않아도 되서 disable 상태로 둠
        http
                .csrf((auth) -> auth.disable());

        //jwt 이므로
        //form 로그인 방식과 http basic 인증 방식 disable
        http
                .formLogin((auth) -> auth.disable());
        http
                .httpBasic((auth) -> auth.disable());

        //경로별 인가 작업
        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers(HttpMethod.POST, "/login", "/", "/join").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .anyRequest().authenticated());

        //필터를 만들었다면, 등록을 해주어야 한다.
        //필터 추가 LoginFilter()는 인자를 받음(AuthenticationManager() 메소드에 authenticationConfiguration 객체를 넣어야 함) 따라서 등록 필요
        http
                .addFilterAt(new LoginFilter(authenticationManager(authenticationManager)), UsernamePasswordAuthenticationFilter.class);

        //세션 설정
        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }
}
