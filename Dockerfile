# syntax=docker/dockerfile:1
# Build with Gradle from PATH (not ./gradlew) so Linux/CI avoids wrapper chmod/CRLF issues.
FROM eclipse-temurin:17-jdk-jammy AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends wget unzip \
    && rm -rf /var/lib/apt/lists/*

RUN wget -q -O /tmp/gradle.zip https://services.gradle.org/distributions/gradle-7.5.1-bin.zip \
    && unzip -q /tmp/gradle.zip -d /opt \
    && rm /tmp/gradle.zip \
    && ln -s /opt/gradle-7.5.1/bin/gradle /usr/local/bin/gradle

WORKDIR /build
COPY . .
RUN sed -i 's/localhost\:5432/db\:5432/' src/main/resources/application-postgresql.properties

ENV GRADLE_OPTS="-Xmx1536m -XX:MaxMetaspaceSize=384m -Dorg.gradle.daemon=false"
RUN gradle bootJar --no-daemon --stacktrace

FROM eclipse-temurin:17-jre-jammy

RUN mkdir /app
COPY --from=builder /build/build/libs/java-spring-vuly-0.1.0.jar /app/

WORKDIR /app

ENV PWD=/app
CMD ["java", "-Djava.security.egd=file:/dev/./urandom", "-jar", "/app/java-spring-vuly-0.1.0.jar"]
