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
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class JwtAuthFilterTest {

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
    void filter_skipsPublicRoute_postUsers() throws InterruptedException {
        downstream.enqueue(new MockResponse().setResponseCode(201)
            .setHeader("Content-Type", "application/json")
            .setBody("{\"id\":\"u1\"}"));

        webTestClient.post().uri("/users")
            .header("Content-Type", "application/json")
            .bodyValue("{\"email\":\"a@b.com\",\"password\":\"12345678\"}")
            .exchange()
            .expectStatus().isCreated();

        RecordedRequest req = downstream.takeRequest();
        assertThat(req.getHeader("X-User-Id")).isNull();
        assertThat(req.getHeader("X-User-Role")).isNull();
    }

    @Test
    void filter_rejectsEmptyBearerToken() {
        // An empty bearer ("Bearer " with no token) is MALFORMED, not a bad signature,
        // so per IRD-003's contract the gateway returns "authorization header required".
        webTestClient.get().uri("/tasks")
            .header("Authorization", "Bearer ")
            .exchange()
            .expectStatus().isUnauthorized()
            .expectBody()
            .jsonPath("$.message").isEqualTo("authorization header required");
    }

    @Test
    void filter_preservesAuthorizationHeaderDownstream() throws InterruptedException {
        String token = TestJwtHelper.validToken("user-42", "member");
        when(redisTemplate.hasKey(anyString())).thenReturn(Mono.just(false));

        downstream.enqueue(new MockResponse().setResponseCode(200)
            .setHeader("Content-Type", "application/json")
            .setBody("[]"));

        webTestClient.get().uri("/tasks")
            .header("Authorization", "Bearer " + token)
            .exchange()
            .expectStatus().isOk();

        RecordedRequest forwarded = downstream.takeRequest();
        assertThat(forwarded.getHeader("Authorization")).startsWith("Bearer ");
    }

    @Test
    void filter_setsCorrectClaimsFromJwt() throws InterruptedException {
        String token = TestJwtHelper.validToken("user-lead-99", "lead");
        when(redisTemplate.hasKey(anyString())).thenReturn(Mono.just(false));

        downstream.enqueue(new MockResponse().setResponseCode(200)
            .setHeader("Content-Type", "application/json")
            .setBody("[]"));

        webTestClient.get().uri("/tasks")
            .header("Authorization", "Bearer " + token)
            .exchange()
            .expectStatus().isOk();

        RecordedRequest forwarded = downstream.takeRequest();
        assertThat(forwarded.getHeader("X-User-Id")).isEqualTo("user-lead-99");
        assertThat(forwarded.getHeader("X-User-Role")).isEqualTo("lead");
    }

    @Test
    void filter_returnJsonOnAllAuthErrors() {
        webTestClient.get().uri("/tasks")
            .exchange()
            .expectHeader().contentType("application/json")
            .expectStatus().isUnauthorized();

        String badToken = TestJwtHelper.tokenSignedWithWrongKey("u", "member");
        webTestClient.get().uri("/tasks")
            .header("Authorization", "Bearer " + badToken)
            .exchange()
            .expectHeader().contentType("application/json")
            .expectStatus().isUnauthorized();
    }
}
