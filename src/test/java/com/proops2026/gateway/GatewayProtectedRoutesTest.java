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
class GatewayProtectedRoutesTest {

    private static MockWebServer taskService;
    private static MockWebServer notificationService;

    @Autowired
    private WebTestClient webTestClient;

    @MockBean
    private ReactiveStringRedisTemplate redisTemplate;

    @BeforeAll
    static void setUp() throws IOException {
        taskService = new MockWebServer();
        taskService.start();
        notificationService = new MockWebServer();
        notificationService.start();
    }

    @AfterAll
    static void tearDown() throws IOException {
        taskService.shutdown();
        notificationService.shutdown();
    }

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("gateway.routes.user-service-url",
            () -> "http://localhost:" + taskService.getPort());
        registry.add("gateway.routes.task-service-url",
            () -> "http://localhost:" + taskService.getPort());
        registry.add("gateway.routes.notification-service-url",
            () -> "http://localhost:" + notificationService.getPort());
        registry.add("jwt.public-keys", () -> TestJwtHelper.PUBLIC_KEY_PEM);
    }

    @Test
    void getTasks_missingAuthorization_returns401() {
        webTestClient.get().uri("/tasks")
            .exchange()
            .expectStatus().isUnauthorized()
            .expectBody()
            .jsonPath("$.message").isEqualTo("authorization header required");
    }

    @Test
    void getUsers_missingAuthorization_returns401() {
        webTestClient.get().uri("/users")
            .exchange()
            .expectStatus().isUnauthorized()
            .expectBody()
            .jsonPath("$.message").isEqualTo("authorization header required");
    }

    @Test
    void postUsersWithRole_withoutAuthorization_routesToUserService() throws InterruptedException {
        taskService.enqueue(new MockResponse()
            .setResponseCode(201)
            .setHeader("Content-Type", "application/json")
            .setBody("{\"id\":\"user-1\",\"role\":\"qa_lead\"}"));

        webTestClient.post().uri("/users/with-role")
            .header("Content-Type", "application/json")
            .bodyValue("{\"email\":\"external@example.com\",\"password\":\"password123\",\"role\":\"QA_LEAD\"}")
            .exchange()
            .expectStatus().isCreated()
            .expectBody()
            .jsonPath("$.role").isEqualTo("qa_lead");

        RecordedRequest forwarded = taskService.takeRequest();
        assertThat(forwarded.getMethod()).isEqualTo("POST");
        assertThat(forwarded.getPath()).isEqualTo("/users/with-role");
    }

    @Test
    void getTasks_invalidToken_returns401() {
        String badToken = TestJwtHelper.tokenSignedWithWrongKey("user-1", "member");

        webTestClient.get().uri("/tasks")
            .header("Authorization", "Bearer " + badToken)
            .exchange()
            .expectStatus().isUnauthorized()
            .expectBody()
            .jsonPath("$.message").isEqualTo("invalid or expired token");
    }

    @Test
    void getTasks_expiredToken_returns401() {
        String expired = TestJwtHelper.expiredToken("user-1", "member");

        webTestClient.get().uri("/tasks")
            .header("Authorization", "Bearer " + expired)
            .exchange()
            .expectStatus().isUnauthorized()
            .expectBody()
            .jsonPath("$.message").isEqualTo("invalid or expired token");
    }

    @Test
    void getTasks_revokedToken_returns401() {
        String token = TestJwtHelper.validTokenWithJti("user-1", "member", "revoked-jti");
        when(redisTemplate.hasKey("blacklist:revoked-jti")).thenReturn(Mono.just(true));

        webTestClient.get().uri("/tasks")
            .header("Authorization", "Bearer " + token)
            .exchange()
            .expectStatus().isUnauthorized()
            .expectBody()
            .jsonPath("$.message").isEqualTo("token has been revoked");
    }

    @Test
    void getTasks_validToken_injectsHeadersAndForwards() throws InterruptedException {
        String token = TestJwtHelper.validToken("user-42", "member");
        when(redisTemplate.hasKey(anyString())).thenReturn(Mono.just(false));

        taskService.enqueue(new MockResponse()
            .setResponseCode(200)
            .setHeader("Content-Type", "application/json")
            .setBody("[{\"id\":\"task-1\",\"title\":\"Test task\"}]"));

        webTestClient.get().uri("/tasks")
            .header("Authorization", "Bearer " + token)
            .exchange()
            .expectStatus().isOk()
            .expectBody()
            .jsonPath("$[0].id").isEqualTo("task-1");

        RecordedRequest forwarded = taskService.takeRequest();
        assertThat(forwarded.getHeader("X-User-Id")).isEqualTo("user-42");
        assertThat(forwarded.getHeader("X-User-Role")).isEqualTo("member");
    }

    @Test
    void postTasks_validToken_routesToTaskService() throws InterruptedException {
        String token = TestJwtHelper.validToken("user-42", "lead");
        when(redisTemplate.hasKey(anyString())).thenReturn(Mono.just(false));

        taskService.enqueue(new MockResponse()
            .setResponseCode(201)
            .setHeader("Content-Type", "application/json")
            .setBody("{\"id\":\"task-new\",\"title\":\"New task\"}"));

        webTestClient.post().uri("/tasks")
            .header("Authorization", "Bearer " + token)
            .header("Content-Type", "application/json")
            .bodyValue("{\"title\":\"New task\"}")
            .exchange()
            .expectStatus().isCreated();

        RecordedRequest forwarded = taskService.takeRequest();
        assertThat(forwarded.getMethod()).isEqualTo("POST");
        assertThat(forwarded.getPath()).isEqualTo("/tasks");
        assertThat(forwarded.getHeader("X-User-Id")).isEqualTo("user-42");
        assertThat(forwarded.getHeader("X-User-Role")).isEqualTo("lead");
    }

    @Test
    void getUsers_validToken_routesToUserService() throws InterruptedException {
        String token = TestJwtHelper.validToken("user-42", "lead");
        when(redisTemplate.hasKey(anyString())).thenReturn(Mono.just(false));

        taskService.enqueue(new MockResponse()
            .setResponseCode(200)
            .setHeader("Content-Type", "application/json")
            .setBody("[{\"id\":\"user-1\",\"email\":\"lead@example.com\",\"role\":\"lead\"}]"));

        webTestClient.get().uri("/users")
            .header("Authorization", "Bearer " + token)
            .exchange()
            .expectStatus().isOk()
            .expectBody()
            .jsonPath("$[0].id").isEqualTo("user-1");

        RecordedRequest forwarded = taskService.takeRequest();
        assertThat(forwarded.getPath()).isEqualTo("/users");
        assertThat(forwarded.getHeader("X-User-Role")).isEqualTo("lead");
    }

    @Test
    void postUsersAdmin_validToken_routesToUserService() throws InterruptedException {
        String token = TestJwtHelper.validToken("user-42", "lead");
        when(redisTemplate.hasKey(anyString())).thenReturn(Mono.just(false));

        taskService.enqueue(new MockResponse()
            .setResponseCode(201)
            .setHeader("Content-Type", "application/json")
            .setBody("{\"id\":\"user-1\",\"role\":\"member\"}"));

        webTestClient.post().uri("/users/admin")
            .header("Authorization", "Bearer " + token)
            .header("Content-Type", "application/json")
            .bodyValue("{\"email\":\"member@example.com\",\"password\":\"password123\",\"role\":\"member\"}")
            .exchange()
            .expectStatus().isCreated();

        RecordedRequest forwarded = taskService.takeRequest();
        assertThat(forwarded.getMethod()).isEqualTo("POST");
        assertThat(forwarded.getPath()).isEqualTo("/users/admin");
        assertThat(forwarded.getHeader("X-User-Role")).isEqualTo("lead");
    }

    @Test
    void patchUser_validToken_routesToUserService() throws InterruptedException {
        String token = TestJwtHelper.validToken("user-42", "lead");
        when(redisTemplate.hasKey(anyString())).thenReturn(Mono.just(false));

        taskService.enqueue(new MockResponse()
            .setResponseCode(200)
            .setHeader("Content-Type", "application/json")
            .setBody("{\"id\":\"user-1\",\"role\":\"lead\"}"));

        webTestClient.patch().uri("/users/user-1")
            .header("Authorization", "Bearer " + token)
            .header("Content-Type", "application/json")
            .bodyValue("{\"role\":\"lead\"}")
            .exchange()
            .expectStatus().isOk();

        RecordedRequest forwarded = taskService.takeRequest();
        assertThat(forwarded.getMethod()).isEqualTo("PATCH");
        assertThat(forwarded.getPath()).isEqualTo("/users/user-1");
    }

    @Test
    void deleteUser_validToken_routesToUserService() throws InterruptedException {
        String token = TestJwtHelper.validToken("user-42", "lead");
        when(redisTemplate.hasKey(anyString())).thenReturn(Mono.just(false));

        taskService.enqueue(new MockResponse().setResponseCode(204));

        webTestClient.delete().uri("/users/user-1")
            .header("Authorization", "Bearer " + token)
            .exchange()
            .expectStatus().isNoContent();

        RecordedRequest forwarded = taskService.takeRequest();
        assertThat(forwarded.getMethod()).isEqualTo("DELETE");
        assertThat(forwarded.getPath()).isEqualTo("/users/user-1");
    }

    @Test
    void getTaskById_validToken_routesToTaskService() throws InterruptedException {
        String token = TestJwtHelper.validToken("user-42", "member");
        when(redisTemplate.hasKey(anyString())).thenReturn(Mono.just(false));

        taskService.enqueue(new MockResponse()
            .setResponseCode(200)
            .setHeader("Content-Type", "application/json")
            .setBody("{\"id\":\"task-1\",\"title\":\"Test task\"}"));

        webTestClient.get().uri("/tasks/task-1")
            .header("Authorization", "Bearer " + token)
            .exchange()
            .expectStatus().isOk();

        RecordedRequest forwarded = taskService.takeRequest();
        assertThat(forwarded.getPath()).isEqualTo("/tasks/task-1");
    }

    @Test
    void patchTaskAssign_validToken_routesToTaskService() throws InterruptedException {
        String token = TestJwtHelper.validToken("user-42", "lead");
        when(redisTemplate.hasKey(anyString())).thenReturn(Mono.just(false));

        taskService.enqueue(new MockResponse()
            .setResponseCode(200)
            .setHeader("Content-Type", "application/json")
            .setBody("{\"id\":\"task-1\"}"));

        webTestClient.patch().uri("/tasks/task-1/assign")
            .header("Authorization", "Bearer " + token)
            .header("Content-Type", "application/json")
            .bodyValue("{\"assigneeId\":\"user-99\"}")
            .exchange()
            .expectStatus().isOk();

        RecordedRequest forwarded = taskService.takeRequest();
        assertThat(forwarded.getPath()).isEqualTo("/tasks/task-1/assign");
    }

    @Test
    void patchTaskStatus_validToken_routesToTaskService() throws InterruptedException {
        String token = TestJwtHelper.validToken("user-42", "member");
        when(redisTemplate.hasKey(anyString())).thenReturn(Mono.just(false));

        taskService.enqueue(new MockResponse()
            .setResponseCode(200)
            .setHeader("Content-Type", "application/json")
            .setBody("{\"id\":\"task-1\"}"));

        webTestClient.patch().uri("/tasks/task-1/status")
            .header("Authorization", "Bearer " + token)
            .header("Content-Type", "application/json")
            .bodyValue("{\"status\":\"in_progress\"}")
            .exchange()
            .expectStatus().isOk();

        RecordedRequest forwarded = taskService.takeRequest();
        assertThat(forwarded.getPath()).isEqualTo("/tasks/task-1/status");
    }

    @Test
    void patchTaskMetadata_validToken_routesToTaskService() throws InterruptedException {
        String token = TestJwtHelper.validToken("user-42", "lead");
        when(redisTemplate.hasKey(anyString())).thenReturn(Mono.just(false));

        taskService.enqueue(new MockResponse()
            .setResponseCode(200)
            .setHeader("Content-Type", "application/json")
            .setBody("{\"id\":\"task-1\"}"));

        webTestClient.patch().uri("/tasks/task-1/metadata")
            .header("Authorization", "Bearer " + token)
            .header("Content-Type", "application/json")
            .bodyValue("{\"priority\":\"high\"}")
            .exchange()
            .expectStatus().isOk();

        RecordedRequest forwarded = taskService.takeRequest();
        assertThat(forwarded.getPath()).isEqualTo("/tasks/task-1/metadata");
    }

    @Test
    void deleteTask_validToken_routesToTaskService() throws InterruptedException {
        String token = TestJwtHelper.validToken("user-42", "lead");
        when(redisTemplate.hasKey(anyString())).thenReturn(Mono.just(false));

        taskService.enqueue(new MockResponse().setResponseCode(204));

        webTestClient.delete().uri("/tasks/task-1")
            .header("Authorization", "Bearer " + token)
            .exchange()
            .expectStatus().isNoContent();

        RecordedRequest forwarded = taskService.takeRequest();
        assertThat(forwarded.getMethod()).isEqualTo("DELETE");
        assertThat(forwarded.getPath()).isEqualTo("/tasks/task-1");
    }

    @Test
    void postTaskComments_validToken_routesToTaskService() throws InterruptedException {
        String token = TestJwtHelper.validToken("user-42", "member");
        when(redisTemplate.hasKey(anyString())).thenReturn(Mono.just(false));

        taskService.enqueue(new MockResponse()
            .setResponseCode(201)
            .setHeader("Content-Type", "application/json")
            .setBody("{\"id\":\"comment-1\"}"));

        webTestClient.post().uri("/tasks/task-1/comments")
            .header("Authorization", "Bearer " + token)
            .header("Content-Type", "application/json")
            .bodyValue("{\"content\":\"Great work!\"}")
            .exchange()
            .expectStatus().isCreated();

        RecordedRequest forwarded = taskService.takeRequest();
        assertThat(forwarded.getMethod()).isEqualTo("POST");
        assertThat(forwarded.getPath()).isEqualTo("/tasks/task-1/comments");
    }

    @Test
    void getNotifications_validToken_routesToNotificationService() throws InterruptedException {
        String token = TestJwtHelper.validToken("user-42", "member");
        when(redisTemplate.hasKey(anyString())).thenReturn(Mono.just(false));

        notificationService.enqueue(new MockResponse()
            .setResponseCode(200)
            .setHeader("Content-Type", "application/json")
            .setBody("[{\"id\":\"notif-1\",\"message\":\"You were assigned\"}]"));

        webTestClient.get().uri("/notifications")
            .header("Authorization", "Bearer " + token)
            .exchange()
            .expectStatus().isOk()
            .expectBody()
            .jsonPath("$[0].id").isEqualTo("notif-1");

        RecordedRequest forwarded = notificationService.takeRequest();
        assertThat(forwarded.getPath()).isEqualTo("/notifications");
        assertThat(forwarded.getHeader("X-User-Id")).isEqualTo("user-42");
    }

    @Test
    void patchNotificationRead_validToken_routesToNotificationService() throws InterruptedException {
        String token = TestJwtHelper.validToken("user-42", "member");
        when(redisTemplate.hasKey(anyString())).thenReturn(Mono.just(false));

        notificationService.enqueue(new MockResponse()
            .setResponseCode(200)
            .setHeader("Content-Type", "application/json")
            .setBody("{\"id\":\"notif-1\",\"isRead\":true}"));

        webTestClient.patch().uri("/notifications/notif-1/read")
            .header("Authorization", "Bearer " + token)
            .exchange()
            .expectStatus().isOk()
            .expectBody()
            .jsonPath("$.isRead").isEqualTo(true);

        RecordedRequest forwarded = notificationService.takeRequest();
        assertThat(forwarded.getPath()).isEqualTo("/notifications/notif-1/read");
    }

    @Test
    void getTasks_malformedAuthorizationHeader_returns401() {
        webTestClient.get().uri("/tasks")
            .header("Authorization", "NotBearer sometoken")
            .exchange()
            .expectStatus().isUnauthorized()
            .expectBody()
            .jsonPath("$.message").isEqualTo("authorization header required");
    }

    @Test
    void getTasks_validToken_stripsClientSuppliedXUserHeaders() throws InterruptedException {
        String token = TestJwtHelper.validToken("user-42", "member");
        when(redisTemplate.hasKey(anyString())).thenReturn(Mono.just(false));

        taskService.enqueue(new MockResponse()
            .setResponseCode(200)
            .setHeader("Content-Type", "application/json")
            .setBody("[]"));

        webTestClient.get().uri("/tasks")
            .header("Authorization", "Bearer " + token)
            .header("X-User-Id", "spoofed-user")
            .header("X-User-Role", "lead")
            .exchange()
            .expectStatus().isOk();

        RecordedRequest forwarded = taskService.takeRequest();
        assertThat(forwarded.getHeader("X-User-Id")).isEqualTo("user-42");
        assertThat(forwarded.getHeader("X-User-Role")).isEqualTo("member");
    }

    @Test
    void getNotifications_missingAuthorization_returns401() {
        webTestClient.get().uri("/notifications")
            .exchange()
            .expectStatus().isUnauthorized()
            .expectBody()
            .jsonPath("$.message").isEqualTo("authorization header required");
    }

    @Test
    void downstreamErrorBody_passedThroughUnchanged() throws InterruptedException {
        String token = TestJwtHelper.validToken("user-42", "member");
        when(redisTemplate.hasKey(anyString())).thenReturn(Mono.just(false));

        taskService.enqueue(new MockResponse()
            .setResponseCode(400)
            .setHeader("Content-Type", "application/json")
            .setBody("{\"message\":\"title is required\"}"));

        webTestClient.post().uri("/tasks")
            .header("Authorization", "Bearer " + token)
            .header("Content-Type", "application/json")
            .bodyValue("{}")
            .exchange()
            .expectStatus().isBadRequest()
            .expectBody()
            .jsonPath("$.message").isEqualTo("title is required");

        taskService.takeRequest();
    }
}
