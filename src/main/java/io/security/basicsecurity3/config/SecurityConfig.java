package io.security.basicsecurity3.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import jakarta.servlet.http.HttpSession;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public UserDetailsService userDetailsService(){

        UserDetails user = User.builder()
            .username("user")
            .password("{noop}1111")
            .roles("USER")
            .build();

        UserDetails sys = User.builder()
            .username("sys")
            .password("{noop}1111")
            .roles("SYS")
            .build();

        UserDetails admin = User.builder()
            .username("admin")
            .password("{noop}1111")
            .roles("ADMIN")
            .build();

        return new InMemoryUserDetailsManager(user, sys, admin);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
            .authorizeHttpRequests(requests -> {
                requests
                    .requestMatchers("/user").hasRole("USER")
                    .requestMatchers("/admin/pay").hasRole("ADMIN")
                    .requestMatchers("/admin/**").hasAnyRole("ADMIN", "SYS")
                    .anyRequest().authenticated(); // 어떠한 요청이든 인증을 받아야 서버 내 자원 접근 가능
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
                        // System.out.println("authentication : " + authentication.getName());
                        // response.sendRedirect("/");

                        // 로그인 성공 시 기존 요청 url 이동 처리
                        RequestCache requestCache = new HttpSessionRequestCache();
                        SavedRequest savedRequest = requestCache.getRequest(request, response);
                        String redirectUrl = savedRequest.getRedirectUrl();
                        response.sendRedirect(redirectUrl);

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
                    .userDetailsService(userDetailsService()); // 사용자 정보 조회시 필요한 서비스 객체
            })
            .sessionManagement(session -> { // 세션 관리 기능이 작동함
                session
                    .invalidSessionUrl("/login?error") // 세션이 유효하지 않을 때 이동 할 페이지
                    .sessionFixation().changeSessionId() // 사용자 인증 성공시 기존 사용자의 세션 ID만 바꾼다. 서블릿 3.1 이상의 기본값
                    .maximumSessions(1) // 최대 허용 가능 세션 수, -1 : 무제한 로그인 세션 허용
                    .maxSessionsPreventsLogin(false) // 동시 로그인 차단함, false : 기존 세션 만료(default)
                    .expiredUrl("/login?error"); // 세션이 만료된 경우 이동 할 페이지
            })
            .exceptionHandling(exception -> { // 예외처리 기능이 작동함
                exception
                    // .authenticationEntryPoint((request, response, authException) -> {
                    //     // 인증 예외 발생 시 처리하는 인터페이스 구현
                    // })
                    .accessDeniedHandler((request, response, accessDeniedException) -> {
                        // 인가 예외 발생시 처리하는 인터페이스 구현. 인가 예외 페이지 이동
                        response.sendRedirect("/denied");
                    });
            })
            .build();
    }
}
