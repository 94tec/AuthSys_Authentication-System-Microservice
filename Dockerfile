# Stage 1: Build the Spring Boot application using virtual thread optimizations
FROM maven:3.9.9-eclipse-temurin-21 AS build
WORKDIR /app
COPY . .
RUN mvn clean package -Dmaven.test.skip=true

# Stage 2: Production microservice runtime
FROM eclipse-temurin:21-jre-alpine AS runtime

# Security Hardening: Create a non-root system group and user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
WORKDIR /app

# Safely extract the compiled JAR asset from the build environment stage
COPY --from=build /app/target/*.jar app.jar
RUN chown -R appuser:appgroup /app

# Switch to the unprivileged execution identity context
USER appuser

# Expose your application port configuration profile matching Render limits
EXPOSE 8001

# Run with G1 Garbage Collector performance flags suited for low-memory infrastructure
ENV JAVA_OPTS="-XX:+UseG1GC -XX:MaxRAMPercentage=75.0 -XX:+HeapDumpOnOutOfMemoryError"
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar app.jar"]
