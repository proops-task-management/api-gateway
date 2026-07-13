FROM maven:3.9-eclipse-temurin-21 AS builder
WORKDIR /app
COPY pom.xml .
RUN mvn dependency:go-offline
COPY src ./src
RUN mvn package -Dmaven.test.skip=true

FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
COPY --from=builder /app/target/*.jar app.jar
EXPOSE 8080
USER nobody
# Heap sizes relative to the container memory LIMIT (not the host) — the JVM reads
# cgroup limits and takes 75% for heap. Set here (JVM startup), never in application.yml.
# k8s/chart can override this env without rebuilding the image (IRD-003 amend, IRD-017).
ENV JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=75.0"
# Liveness for orchestrators + satisfies Trivy DS-0026. Hits the gateway's own
# GET /health (direct 200, no auth). wget ships with the alpine busybox base.
HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/health || exit 1
CMD ["java", "-jar", "app.jar"]

