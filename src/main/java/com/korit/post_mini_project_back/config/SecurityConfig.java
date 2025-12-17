package com.korit.post_mini_project_back.config;

import com.korit.post_mini_project_back.filter.JwtAuthenticationFilter;
import com.korit.post_mini_project_back.security.JwtAuthenticationEntryPoint;
import com.korit.post_mini_project_back.security.OAuth2SuccessHandler;
import com.korit.post_mini_project_back.service.OAuth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final OAuth2UserService oAuth2UserService;
    private final OAuth2SuccessHandler oAuth2SuccessHandler;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // 허용범위 설정 (밑에있는 corsConfigurationSource 안에 자세한 설정)
        http.cors(cors -> cors.configurationSource(corsConfigurationSource()));

        // 대부분 프로젝트가 CSR이기 때문에 필요없는 설정들이라 비활성화 그냥 외워야 할듯

        // JWT 쓰니까 서버에 세션안만듬 STATELESS로 지정 (JWT는 토큰 방식이라 서버가 기억할 필요가 없음 이거 쌤이 말했던거같음)
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        // HTTP 기본 인증(아이디/비번을 매번 헤더에 담는 방식)을 비활성화
        http.httpBasic(httpBasic -> httpBasic.disable());

        // 우리가 만든 로그인화면 쓸거라서 스프링 시큐리티가 기본으로 제공하는 '로그인 HTML 폼'을 비활성화
        http.formLogin(formLogin -> formLogin.disable());

        // 이건 그냥 세션인증방식에서만 필요한거라고 함;
        http.csrf(csrf -> csrf.disable());


        http.oauth2Login(oauth2 ->
                oauth2.userInfoEndpoint(userInfo -> userInfo.userService(oAuth2UserService))
                        .successHandler(oAuth2SuccessHandler)
        );

        // 5. 필터 순서: 일반 로그인 필터 앞에 우리가 만든 'JWT 검사 필터'를 끼워 넣음, 여기서 토큰이 확인되면 PrincipalUser 생성
        http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        http.authorizeHttpRequests(auth -> {
            auth.requestMatchers("/api/auth/**").permitAll();
            auth.requestMatchers("/v3/api-docs/**").permitAll();
            auth.requestMatchers("/swagger-ui/**").permitAll();
            auth.requestMatchers("/swagger-ui.html").permitAll();
            auth.requestMatchers("/doc").permitAll();
            auth.anyRequest().authenticated();
        });

        // 이거는시큐리티라이브러리의특징인데jwt필터를통과하지모다면어떤문제가생기냐면로그인페이지로강제이동시킴그런데로그인할수잇는환경을다비활성화시키고oauth2login만남겨놓은겨그래서302뜨면서다시로그인페이지로돌아감
        // 실패시 401 반환, 인증 실패
        http.exceptionHandling(exception -> exception.authenticationEntryPoint(jwtAuthenticationEntryPoint));

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {

        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.setAllowedOrigins(List.of("http://localhost:5173"));
        corsConfiguration.setAllowedMethods(List.of("*"));
        corsConfiguration.setAllowedHeaders(List.of("*"));
        corsConfiguration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfiguration);

        return source;

    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}