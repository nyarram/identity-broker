# syntax=docker/dockerfile:1
# Builds one Spring Boot service. Usage: docker build --build-arg SERVICE=broker .

FROM eclipse-temurin:21-jdk AS build
WORKDIR /src
COPY gradlew settings.gradle ./
COPY gradle gradle
COPY broker/build.gradle broker/
COPY orders-api/build.gradle orders-api/
COPY broker/src broker/src
COPY orders-api/src orders-api/src
ARG SERVICE
RUN --mount=type=cache,target=/root/.gradle ./gradlew --no-daemon -q ":${SERVICE}:bootJar"

FROM eclipse-temurin:21-jre
ARG SERVICE
RUN groupadd --system app && useradd --system --gid app app \
    && mkdir -p /var/lib/broker && chown app:app /var/lib/broker
COPY --from=build "/src/${SERVICE}/build/libs/${SERVICE}.jar" /app/app.jar
USER app
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-jar", "/app/app.jar"]
