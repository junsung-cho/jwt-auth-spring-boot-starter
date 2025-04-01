# JWT Auth Spring Boot Starter

The **JWT Authorization Spring Boot Starter** is designed to simplify the implementation of JSON Web Token (JWT) based
authentication and authorization within Spring Boot applications. This starter provides a robust foundation for
developers looking to secure their Spring Boot applications using JWT, a widely adopted industry standard for
token-based authentication.

## Features

- **JWT-based authentication** for secure REST APIs.
- Easy integration with Spring Boot applications.
- Based on Spring Security.

## Getting Started

### Dependency Setup

Add the dependency to your project.

#### Maven

```xml

<dependency>
    <groupId>dev.junsung</groupId>
    <artifactId>jwt-auth-spring-boot-starter</artifactId>
    <version>0.0.5</version>
</dependency>
```

#### Gradle

```kotlin
implementation("dev.junsung:jwt-auth-spring-boot-starter:0.0.5")
```

### Usage

#### Step 1: Add Required Dependencies

Include the following dependencies in your `build.gradle.kts` file:

```kotlin
dependencies {
    implementation("org.springframework.boot:spring-boot-starter-oauth2-resource-server")
    implementation("dev.junsung:jwt-auth-spring-boot-starter:0.0.5")
}
```

#### Step 2: Configure Security Filter Chain

Set up your **SecurityFilterChain** to include JWT authentication. Add `authorizationServer` configuration as shown
below:

```kotlin
@Configuration
@EnableWebSecurity
class SecurityConfig {
    @Bean
    fun filterChain(http: HttpSecurity): SecurityFilterChain {
        return http
            // Additional security configurations...
            .oauth2ResourceServer { it.jwt {} }
            .authorizationServer { }
            .build()
    }
}
```

## Additional Notes

- The **JWT Auth Spring Boot Starter** depends on Spring Security's OAuth2 components.
- Ensure you have the proper Spring Security configurations to protect your endpoints.
