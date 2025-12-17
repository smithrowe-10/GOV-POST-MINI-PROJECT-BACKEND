package com.korit.post_mini_project_back.filter;

import com.korit.post_mini_project_back.entity.User;
import com.korit.post_mini_project_back.jwt.JwtTokenProvider;
import com.korit.post_mini_project_back.mapper.UserMapper;
import com.korit.post_mini_project_back.security.PrincipalUser;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final UserMapper userMapper;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // 프론트엔드 인터셉터가 넣어준 "Authorization" 헤더를 꺼냄 (axiosConfig.js 14번줄 참고)
        String bearerToken = request.getHeader("Authorization");

        // 만약 헤더가 없거나 "Bearer "로 시작하지 않으면 그냥 통과 (이때 로그인이 필요한 서비스라면 뒤에서 401 에러가 터짐)
        if (bearerToken == null || !bearerToken.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // "Bearer " 글자를 떼어내고 순수한 토큰(JWT)만 추출
        String accessToken = bearerToken.replaceAll("Bearer ", "");

        // 토큰이 조작되지는 않았는지, 만료되지는 않았는지 검사 (지 알아서 해주는 부분이라 머 알빠 X)
        if(!jwtTokenProvider.validateToken(accessToken)) {
            filterChain.doFilter(request, response);
            return;
        }

        // 토큰 주머니 안에서 유저의 고유 ID(userId)를 꺼냄
        int userId = jwtTokenProvider.getUserId(accessToken);

        // 꺼낸 ID로 DB에서 실제 유저가 존재하는지 찾아봄
        // 없다면 그냥 통과
        User foundUser = userMapper.findByUserId(userId);
        if (foundUser == null) {
            filterChain.doFilter(request, response);
            return;
        }

        // 그냥 이거 자체가 UsernamePasswordAuthenticationToken 검증을 통과하기 위한 로직임..
        // 유저의 권한(Role)을 생성 참고로 DB에는 OAUTH2_USER 이렇게 나와있음
        Collection<? extends GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority(foundUser.getRole()));

        // 위에서 만든 신분증(PrincipalUser)을 새로 발급
        PrincipalUser principalUser = new PrincipalUser(authorities, Map.of("id", foundUser.getOauth2Id()), "id", foundUser);
        String password = "";

        // 시큐리티 전용 인증 도장(AuthenticationToken)을 찍음
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(principalUser, password, authorities);

        // [핵심] 이 도장을 SecurityContextHolder라는 '보관함'에 넣습니다. 이제부터 Controller에서는 @AuthenticationPrincipal로 이 정보를 바로 꺼내 쓸 수 있습니다.
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        filterChain.doFilter(request, response);

    }
}
