# ------------ Build stage ------------
# Use Maven with JDK 17 to compile the application
FROM maven:3.9.6-eclipse-temurin-17 AS build
WORKDIR /workspace

# Copy pom files separately to leverage Docker layer caching
COPY pom.xml .
COPY one-auth-app/pom.xml one-auth-app/pom.xml
COPY one-auth-jar/pom.xml one-auth-jar/pom.xml

# Copy sources and build the application
COPY one-auth-app/src one-auth-app/src
COPY one-auth-jar/src one-auth-jar/src
RUN mvn -pl one-auth-app -am -DskipTests package

# ------------ Runtime stage ------------
# Use a minimal JRE to run the built jar
FROM eclipse-temurin:17-jre
WORKDIR /app
COPY --from=build /workspace/one-auth-app/target/one-auth-app-0.0.1-SNAPSHOT.jar app.jar

# Expose application port and run
EXPOSE 8080
ENTRYPOINT ["java","-jar","app.jar"]
