package com.proops2026.gateway;

import java.io.IOException;

import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class GlobalExceptionHandlerTest {

    private static MockWebServer downstream;

    @Autowired
    private WebTestClient webTestClient;

    @MockBean
    private ReactiveStringRedisTemplate redisTemplate;

    @BeforeAll
    static void setUp() throws IOException {
        downstream = new MockWebServer();
        downstream.start();
    }

    @AfterAll
    static void tearDown() throws IOException {
        downstream.shutdown();
    }

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("gateway.routes.user-service-url",
            () -> "http://localhost:" + downstream.getPort());
        registry.add("gateway.routes.task-service-url",
            () -> "http://localhost:" + downstream.getPort());
        registry.add("gateway.routes.notification-service-url",
            () -> "http://localhost:" + downstream.getPort());
        registry.add("jwt.public-keys", () -> TestJwtHelper.PUBLIC_KEY_PEM);
    }

    @Test
    void unknownPath_returnsJsonNotFound() {
        webTestClient.get().uri("/does/not/exist")
            .exchange()
            .expectStatus().isNotFound()
            .expectHeader().contentType(MediaType.APPLICATION_JSON)
            .expectBody()
            .jsonPath("$.message").isEqualTo("not found");
    }

    @Test
    void unknownPath_post_returnsJsonNotFound() {
        webTestClient.post().uri("/nonexistent")
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue("{}")
            .exchange()
            .expectStatus().isNotFound()
            .expectHeader().contentType(MediaType.APPLICATION_JSON)
            .expectBody()
            .jsonPath("$.message").isEqualTo("not found");
    }

    @Test
    void unknownPath_neverReturnsHtml() {
        webTestClient.get().uri("/random/path")
            .header("Accept", "text/html")
            .exchange()
            .expectStatus().isNotFound()
            .expectHeader().contentType(MediaType.APPLICATION_JSON)
            .expectBody()
            .jsonPath("$.message").isEqualTo("not found");
    }
}
