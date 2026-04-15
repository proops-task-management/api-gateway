package com.proops2026.gateway.filter;

import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.proops2026.gateway.util.JwtUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.core.Ordered;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthFilter implements GlobalFilter, Ordered {

    private static final String AUTH_REQUIRED_METADATA = "authRequired";

    private final JwtUtil jwtUtil;
    private final ReactiveStringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        Route route = exchange.getAttribute(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR);
        if (!requiresAuth(route)) {
            return chain.filter(exchange);
        }

        String token = extractBearerToken(exchange.getRequest());
        if (token == null) {
            return writeJson(exchange, HttpStatus.UNAUTHORIZED, "authorization header required");
        }

        Claims claims;
        try {
            claims = jwtUtil.parseAndValidate(token);
        } catch (JwtException | IllegalArgumentException ex) {
            log.warn("Rejected request with invalid token for path {}", exchange.getRequest().getPath().value());
            return writeJson(exchange, HttpStatus.UNAUTHORIZED, "invalid or expired token");
        }

        String tokenId = claims.getId();
        if (tokenId == null || tokenId.isBlank()) {
            return writeJson(exchange, HttpStatus.UNAUTHORIZED, "invalid or expired token");
        }

        return redisTemplate.hasKey(blacklistKey(tokenId))
            .flatMap(blacklisted -> {
                if (Boolean.TRUE.equals(blacklisted)) {
                    log.warn("Rejected revoked token for path {}", exchange.getRequest().getPath().value());
                    return writeJson(exchange, HttpStatus.UNAUTHORIZED, "token has been revoked");
                }
                return chain.filter(mutateExchange(exchange, claims));
            });
    }

    @Override
    public int getOrder() {
        return -100;
    }

    private boolean requiresAuth(Route route) {
        if (route == null) {
            return false;
        }
        Object metadata = route.getMetadata().get(AUTH_REQUIRED_METADATA);
        return Boolean.TRUE.equals(metadata);
    }

    private String extractBearerToken(ServerHttpRequest request) {
        String authorization = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            return null;
        }
        return authorization.substring(7).trim();
    }

    private ServerWebExchange mutateExchange(ServerWebExchange exchange, Claims claims) {
        ServerHttpRequest mutatedRequest = exchange.getRequest()
            .mutate()
            .headers(headers -> {
                headers.remove("X-User-Id");
                headers.remove("X-User-Role");
                headers.set("X-User-Id", claims.get("userId", String.class));
                headers.set("X-User-Role", claims.get("role", String.class));
            })
            .build();

        return exchange.mutate().request(mutatedRequest).build();
    }

    private String blacklistKey(String tokenId) {
        return "blacklist:" + tokenId;
    }

    private Mono<Void> writeJson(ServerWebExchange exchange, HttpStatus status, String message) {
        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        return Mono.fromSupplier(() -> {
                try {
                    return objectMapper.writeValueAsBytes(Map.of("message", message));
                } catch (JsonProcessingException ex) {
                    return "{\"message\":\"internal server error\"}".getBytes();
                }
            })
            .flatMap(bytes -> exchange.getResponse().writeWith(Mono.just(
                exchange.getResponse().bufferFactory().wrap(bytes))));
    }
}

