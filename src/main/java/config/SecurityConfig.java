package config;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@RequiredArgsConstructor
@EnableWebFluxSecurity
public class SecurityConfig {

    private final JwtFilterConfig jwtFilter;

    @Value("${front-ip}")
    private String frontIp;

    @Bean
    public SecurityWebFilterChain filterChain(ServerHttpSecurity http) {
        return http
                .cors(withDefaults())
                .csrf(csrf -> csrf.disable())
                .authorizeExchange(exchange -> exchange
                        .pathMatchers("/auth/url", "/auth/login","/auth/refresh", "/login").permitAll()
                        .anyExchange().authenticated()
                )
                .addFilterAt(jwtFilter, org.springframework.security.config.web.server.SecurityWebFiltersOrder.AUTHENTICATION)
                .build();
    }

    @Bean
    public CorsWebFilter corsWebFilter() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of("http://localhost:3000"));
        config.setAllowedMethods(List.of("*"));
        config.setAllowedHeaders(List.of("*"));
        config.setExposedHeaders(Arrays.asList("Authorization", "X-User-Email", "X-User-Role"));
        config.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);

        return new CorsWebFilter(source);
    }
}
