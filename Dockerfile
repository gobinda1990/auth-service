# ---------- Stage 1: Build with Maven ----------
FROM maven:3.9.6-eclipse-temurin-17 AS builder

# Set working directory
WORKDIR /app

# Copy project files
COPY pom.xml ./
COPY src ./src

# Build JAR (skip tests for speed)
RUN mvn clean package -DskipTests

# ---------- Stage 2: Run with lightweight JRE ----------
FROM eclipse-temurin:17-jre-alpine

# Set working directory
WORKDIR /app

# Copy built JAR from builder stage
COPY --from=builder /app/target/*.jar app.jar

# Expose application port
EXPOSE 8081

# Health check (optional but recommended)
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget -qO- http://localhost:8081/actuator/health || exit 1

# Run the service
ENTRYPOINT ["java", "-jar", "app.jar"]
