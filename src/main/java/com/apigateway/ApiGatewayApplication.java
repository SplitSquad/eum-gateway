package com.apigateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;

@EnableDiscoveryClient
@SpringBootApplication
@ComponentScan(basePackages = {"com.apigateway", "config", "util"})
public class ApiGatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(ApiGatewayApplication.class, args);
    }
    @Bean
    public RouteLocator ecomRouteLocator(RouteLocatorBuilder builder) {
        return builder.routes()
                // 개별 라우트 등록
                // 서비스별 URL 별칭이 1개인 경우, n개인 경우도 존재
                .route("user",
                        r -> r.path("/login").uri("lb://community")) //test

            
                .route("user",
                        r -> r.path("/auth/**").uri("lb://user"))
                .route("user",
                r -> r.path("/users/**").uri("lb://user"))
                .route("user",
                        r -> r.path("/calendar/**").uri("lb://user"))
                .route("post",
                        r -> r.path("/community/**").uri("lb://community"))
                .route("debate",
                        r -> r.path("/debate/**").uri("lb://debate"))
                .route("alarm",
                        r -> r.path("/alarms/**").uri("lb://alarm"))
                .route("alarm",
                        r -> r.path("/sse/**").uri("lb://alarm"))
                .route("log",
                        r -> r.path("/logs/**").uri("lb://log"))

                .route("EUM-CHATBOT",
                        r -> r.path("/api/v1/chatbot").uri("lb://EUM-CHATBOT"))
                .route("EUM-DISCUSSION-ROOM",
                        r -> r.path("/api/v1/discussion").uri("lb://EUM-DISCUSSION-ROOM"))
                .route("classfier", 
                        r -> r.path("/user/**").uri("lb://classfier"))
                .build();
    }
}
