package com.proops2026.gateway;

import java.io.IOException;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.bean.MockBean;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class GatewayPublicRoutesTest {

    private static MockWebServer userService;

    @Autowired
    private WebTestClient webTestClient;

    @MockBean
    private ReactiveStringRedisTemplate redisTemplate;

    @BeforeAll
    static void setUp() throws IOException {
        userService = new MockWebServer();
        userService.start();
    }

    @AfterAll
    static void tearDown() throws IOException {
        userService.shutdown();
    }

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("gateway.routes.user-service-url",
            () -> "http://localhost:" + userService.getPort());
        registry.add("gateway.routes.task-service-url",
            () -> "http://localhost:" + userService.getPort());
        registry.add("gateway.routes.notification-service-url",
            () -> "http://localhost:" + userService.getPort());
        registry.add("jwt.secret", () -> TestJwtHelper.SECRET);
    }

    @Test
    void postUsers_withoutAuthorization_proxiesToUserService() throws InterruptedException {
        userService.enqueue(new MockResponse()
            .setResponseCode(201)
            .setHeader("Content-Type", "application/json")
            .setBody("{\"id\":\"abc-123\",\"email\":\"user@test.com\",\"created_at\":\"2026-04-16T00:00:00Z\"}"));

        webTestClient.post().uri("/users")
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue("{\"email\":\"user@test.com\",\"password\":\"password123\"}")
            .exchange()
            .expectStatus().isCreated()
            .expectBody()
            .jsonPath("$.id").isEqualTo("abc-123")
            .jsonPath("$.email").isEqualTo("user@test.com");

        RecordedRequest request = userService.takeRequest();
        assertThat(request.getMethod()).isEqualTo("POST");
        assertThat(request.getPath()).isEqualTo("/users");
    }

    @Test
    void postAuthLogin_withoutAuthorization_proxiesToUserService() throws InterruptedException {
        userService.enqueue(new MockResponse()
            .setResponseCode(200)
            .setHeader("Content-Type", "application/json")
            .setBody("{\"token\":\"jwt-token\",\"user\":{\"id\":\"abc-123\",\"email\":\"user@test.com\",\"role\":\"member\"}}"));

        webTestClient.post().uri("/auth/login")
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue("{\"email\":\"user@test.com\",\"password\":\"password123\"}")
            .exchange()
            .expectStatus().isOk()
            .expectBody()
            .jsonPath("$.token").isEqualTo("jwt-token")
            .jsonPath("$.user.role").isEqualTo("member");

        RecordedRequest request = userService.takeRequest();
        assertThat(request.getMethod()).isEqualTo("POST");
        assertThat(request.getPath()).isEqualTo("/auth/login");
    }

    @Test
    void getHealth_returns200() {
        webTestClient.get().uri("/health")
            .exchange()
            .expectStatus().isOk()
            .expectBody()
            .jsonPath("$.status").isEqualTo("ok")
            .jsonPath("$.service").isEqualTo("api-gateway");
    }

    @Test
    void unknownPath_returns404() {
        webTestClient.get().uri("/unknown/path")
            .exchange()
            .expectStatus().isNotFound()
            .expectBody()
            .jsonPath("$.message").isEqualTo("not found");
    }
}
