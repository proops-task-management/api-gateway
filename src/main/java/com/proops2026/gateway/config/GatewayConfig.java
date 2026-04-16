package com.proops2026.gateway.config;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerResponse;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import reactor.core.publisher.Mono;

import static com.proops2026.gateway.filter.JwtAuthFilter.AUTH_REQUIRED_METADATA;
import static org.springframework.web.reactive.function.server.RequestPredicates.GET;

@Slf4j
@Configuration
public class GatewayConfig {

    private final String userServiceUrl;
    private final String taskServiceUrl;
    private final String notificationServiceUrl;
    private final List<String> corsAllowedOrigins;

    public GatewayConfig(
            @Value("${gateway.routes.user-service-url}") String userServiceUrl,
            @Value("${gateway.routes.task-service-url}") String taskServiceUrl,
            @Value("${gateway.routes.notification-service-url}") String notificationServiceUrl,
            @Value("${cors.allowed-origins:http://localhost:3000,http://localhost:5173}") String corsAllowedOrigins) {
        this.userServiceUrl = userServiceUrl;
        this.taskServiceUrl = taskServiceUrl;
        this.notificationServiceUrl = notificationServiceUrl;
        this.corsAllowedOrigins = Arrays.asList(corsAllowedOrigins.split(","));
    }

    @Bean
    public RouteLocator gatewayRoutes(RouteLocatorBuilder builder) {
        return builder.routes()
            .route("users-register", r -> r
                .method(HttpMethod.POST)
                .and()
                .path("/users")
                .metadata(AUTH_REQUIRED_METADATA, false)
                .uri(userServiceUrl))
            .route("auth-login", r -> r
                .method(HttpMethod.POST)
                .and()
                .path("/auth/login")
                .metadata(AUTH_REQUIRED_METADATA, false)
                .uri(userServiceUrl))
            .route("users-list", r -> r
                .method(HttpMethod.GET)
                .and()
                .path("/users")
                .metadata(AUTH_REQUIRED_METADATA, true)
                .uri(userServiceUrl))
            .route("users-get", r -> r
                .method(HttpMethod.GET)
                .and()
                .path("/users/{id}")
                .metadata(AUTH_REQUIRED_METADATA, true)
                .uri(userServiceUrl))
            .route("users-admin-create", r -> r
                .method(HttpMethod.POST)
                .and()
                .path("/users/admin")
                .metadata(AUTH_REQUIRED_METADATA, true)
                .uri(userServiceUrl))
            .route("users-update", r -> r
                .method(HttpMethod.PATCH)
                .and()
                .path("/users/{id}")
                .metadata(AUTH_REQUIRED_METADATA, true)
                .uri(userServiceUrl))
            .route("users-delete", r -> r
                .method(HttpMethod.DELETE)
                .and()
                .path("/users/{id}")
                .metadata(AUTH_REQUIRED_METADATA, true)
                .uri(userServiceUrl))
            .route("tasks-list", r -> r
                .method(HttpMethod.GET)
                .and()
                .path("/tasks")
                .metadata(AUTH_REQUIRED_METADATA, true)
                .uri(taskServiceUrl))
            .route("tasks-create", r -> r
                .method(HttpMethod.POST)
                .and()
                .path("/tasks")
                .metadata(AUTH_REQUIRED_METADATA, true)
                .uri(taskServiceUrl))
            .route("tasks-get", r -> r
                .method(HttpMethod.GET)
                .and()
                .path("/tasks/{id}")
                .metadata(AUTH_REQUIRED_METADATA, true)
                .uri(taskServiceUrl))
            .route("tasks-assign", r -> r
                .method(HttpMethod.PATCH)
                .and()
                .path("/tasks/{id}/assign")
                .metadata(AUTH_REQUIRED_METADATA, true)
                .uri(taskServiceUrl))
            .route("tasks-status", r -> r
                .method(HttpMethod.PATCH)
                .and()
                .path("/tasks/{id}/status")
                .metadata(AUTH_REQUIRED_METADATA, true)
                .uri(taskServiceUrl))
            .route("tasks-metadata", r -> r
                .method(HttpMethod.PATCH)
                .and()
                .path("/tasks/{id}/metadata")
                .metadata(AUTH_REQUIRED_METADATA, true)
                .uri(taskServiceUrl))
            .route("tasks-delete", r -> r
                .method(HttpMethod.DELETE)
                .and()
                .path("/tasks/{id}")
                .metadata(AUTH_REQUIRED_METADATA, true)
                .uri(taskServiceUrl))
            .route("tasks-comments", r -> r
                .method(HttpMethod.POST)
                .and()
                .path("/tasks/{id}/comments")
                .metadata(AUTH_REQUIRED_METADATA, true)
                .uri(taskServiceUrl))
            .route("notifications-list", r -> r
                .method(HttpMethod.GET)
                .and()
                .path("/notifications")
                .metadata(AUTH_REQUIRED_METADATA, true)
                .uri(notificationServiceUrl))
            .route("notifications-read", r -> r
                .method(HttpMethod.PATCH)
                .and()
                .path("/notifications/{id}/read")
                .metadata(AUTH_REQUIRED_METADATA, true)
                .uri(notificationServiceUrl))
            .build();
    }

    @Bean
    public RouterFunction<ServerResponse> gatewayHealthRoute() {
        return RouterFunctions.route(GET("/health"), request ->
            ServerResponse.ok()
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("status", "ok", "service", "api-gateway")));
    }

    @Bean
    public CorsWebFilter corsWebFilter() {
        CorsConfiguration config = new CorsConfiguration();
        corsAllowedOrigins.forEach(config::addAllowedOrigin);
        config.addAllowedMethod("*");
        config.addAllowedHeader("*");
        config.setAllowCredentials(false);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return new CorsWebFilter(source);
    }

    @Bean
    public WebFilter requestLoggingFilter() {
        return (exchange, chain) -> {
            long startTime = System.currentTimeMillis();
            return chain.filter(exchange)
                .doFinally(signalType -> logRequest(exchange, startTime));
        };
    }

    private void logRequest(ServerWebExchange exchange, long startTime) {
        ServerHttpResponse response = exchange.getResponse();
        int status = response.getStatusCode() == null ? 200 : response.getStatusCode().value();
        long durationMs = System.currentTimeMillis() - startTime;
        log.info("[{}] {} {} -> {} ({}ms)",
            java.time.Instant.now(),
            exchange.getRequest().getMethod(),
            exchange.getRequest().getPath().value(),
            status,
            durationMs);
    }
}

