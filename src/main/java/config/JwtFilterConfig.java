package config;

import com.apigateway.entity.UserEntity;
import com.apigateway.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import util.JwtUtil;

import java.util.Collections;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtFilterConfig implements WebFilter {

    @Value("${debate.secret}")
    private String secret;

    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;


    private static final List<String> WHITELIST = List.of(
            "/auth/url",
            "/auth/login",
            "/auth/refresh"
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {

        String path = exchange.getRequest().getURI().getPath();
        if (WHITELIST.stream().anyMatch(path::startsWith)) {
            return chain.filter(exchange);
        }

        String debateHeader = exchange.getRequest().getHeaders().getFirst("Debate"); //토론 작성글은 통과
        if(secret.equals(debateHeader)) {
            return chain.filter(exchange);
        }

        String token = exchange.getRequest().getHeaders().getFirst("Authorization");
        if (token == null) { // 토큰 없으면
            return setErrorResponse(exchange, HttpStatus.UNAUTHORIZED, "AccessToken이 필요합니다.");
        }

        Long userid;
        try {
            userid = jwtUtil.getUserid(token);
        } catch (Exception e) {
            return setErrorResponse(exchange, HttpStatus.UNAUTHORIZED, "잘못된 토큰입니다.");
        }
        System.out.println(userid);

        UserEntity userEntity = userRepository.findById(userid).orElse(null);
        if (userEntity == null) {
            return setErrorResponse(exchange, HttpStatus.UNAUTHORIZED, "사용자 계정이 존재하지 않습니다.");
        }

        if (jwtUtil.isExpired(token)) {
            return setErrorResponse(exchange, HttpStatus.UNAUTHORIZED, "만료된 access 토큰");
        }

        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(
                        userEntity.getEmail(),
                        null,
                        Collections.singleton(() -> userEntity.getRole())
                );

        return chain.filter(
                exchange.mutate()
                        .request(exchange.getRequest().mutate()
                                .header("X-Auth-User", userEntity.getEmail())
                                .build())
                        .build()
        ).contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));
    }

    private Mono<Void> setErrorResponse(ServerWebExchange exchange, HttpStatus status, String message) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        String errorResponse = "{\"error\": \"" + message + "\"}";
        return response.writeWith(Mono.just(response.bufferFactory().wrap(errorResponse.getBytes())));
    }
}