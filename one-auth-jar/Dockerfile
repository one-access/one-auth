# ------------ Build stage ------------
FROM maven:3.9.6-eclipse-temurin-17 AS build
WORKDIR /workspace

# Copy pom files to leverage caching
COPY pom.xml .
COPY one-auth-jar/pom.xml one-auth-jar/pom.xml

# Copy sources and build
COPY one-auth-jar/src one-auth-jar/src
RUN mvn -pl one-auth-jar -am -DskipTests package

# ------------ Runtime stage ------------
FROM eclipse-temurin:17-jre
WORKDIR /app
COPY --from=build /workspace/one-auth-jar/target/one-auth-jar-0.0.1-SNAPSHOT-exec.jar one-auth-app.jar
EXPOSE 8080
ENTRYPOINT ["java","-jar","one-auth-app.jar"]
