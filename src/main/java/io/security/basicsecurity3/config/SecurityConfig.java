package io.security.basicsecurity3.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;

import jakarta.servlet.http.HttpSession;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    UserDetailsService userDetailsService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
            .authorizeHttpRequests(requests -> {
                requests.anyRequest().authenticated(); // 어떠한 요청이든 인증을 받아야 서버 내 자원 접근 가능
            })
            .formLogin(form -> { // form 로그인 인증방식 작동
                form
                    // .loginPage("/loginPage") // 시큐리티에서 제공하는 로그인 페이지가 아닌 커스텀 로그인 페이지 사용
                    .defaultSuccessUrl("/") // 인증 성공시 루트 페이지로 이동
                    .failureUrl("/login") // 인증 실패시 다시 로그인 페이지로 이동
                    .usernameParameter("userId") // username으로 받을 필드 명
                    .passwordParameter("passwd") // password로 받을 필드 명
                    .loginProcessingUrl("/login_proc") // form 요소 action url
                    .successHandler((request, response, authentication) -> {
                        // 로그인 성공시 콘솔에 username 출력 후 루트 페이지로 이동
                        System.out.println("authentication : " + authentication.getName());
                        response.sendRedirect("/");
                    })
                    .failureHandler((request, response, exception) -> {
                        // 로그인 실패시 파라미터로 전달받은 인증예외 객체를 사용해 콘솔에 예외 메세지 출력 후 로그인 페이지로 이동
                        System.out.println("exception : " + exception.getMessage());
                        response.sendRedirect("/login");
                    })
                    .permitAll(); // 커스텀 로그인 페이지는 인증없이 접근 가능하게 설정
            })
            .logout(logout -> { // 로그아웃 기능 작동
                logout
                    .logoutUrl("/logout") // 로그아웃 form action url. post 방식만 지원
                    .logoutSuccessUrl("/login") // 로그아웃 성공시 로그인 페이지로 이동
                    .addLogoutHandler((request, response, authentication) -> {
                        // 기본 핸들러 대신 로그아웃 처리할 핸들러 구현 세션 무효화
                        HttpSession session = request.getSession();
                        session.invalidate();
                    })
                    .logoutSuccessHandler((request, response, authentication) -> {
                        // 로그아웃 성공 후 처리할 핸들러 구현 로그인 페이지로 이동
                        response.sendRedirect("/login");
                    })
                    .deleteCookies("remember")
                ;
            })
            .rememberMe(remember -> { // rememberMe 기능 작동
                remember
                    .rememberMeParameter("remember") // 체크박스 파라미터 명 기본 명은 remember-me
                    .tokenValiditySeconds(3600) // 쿠키 만료 시간 설정(초) 기본 14일
                    .alwaysRemember(false) // 사용자가 체크박스를 활성화하지 않아도 항상 실행 기본 false
                    .userDetailsService(userDetailsService); // 사용자 정보 조회시 필요한 서비스 객체
            })
            .build();
    }
}
