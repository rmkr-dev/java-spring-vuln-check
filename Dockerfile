# syntax=docker/dockerfile:1
# Use the Gradle wrapper with JDK 17 (same as CI). System `gradle` can mis-resolve Spring Boot buildscript plugins.
FROM eclipse-temurin:17-jdk-jammy AS builder

WORKDIR /build
COPY . .

# Fix Windows CRLF on the wrapper script; JDBC host for docker-compose
RUN sed -i 's/\r$//' gradlew && chmod +x gradlew
RUN sed -i 's/localhost\:5432/db\:5432/' src/main/resources/application-postgresql.properties

ENV GRADLE_OPTS="-Xmx2048m -XX:MaxMetaspaceSize=512m -Dfile.encoding=UTF-8 -Dorg.gradle.daemon=false"

# Skip tests/checks (none in repo / avoids flaky validation); wrapper uses Gradle 8.5+ (JDK 17, Spring Boot 3.4).
RUN ./gradlew --no-daemon bootJar --stacktrace -x test -x check

FROM eclipse-temurin:17-jre-jammy

RUN mkdir /app
COPY --from=builder /build/build/libs/java-spring-vuly-0.1.0.jar /app/

WORKDIR /app

ENV PWD=/app
CMD ["java", "-Djava.security.egd=file:/dev/./urandom", "-jar", "/app/java-spring-vuly-0.1.0.jar"]
