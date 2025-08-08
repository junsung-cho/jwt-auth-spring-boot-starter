plugins {
    id("maven-publish")
    id("signing")
    kotlin("jvm") version "2.2.0"
    kotlin("plugin.allopen") version "2.2.0"
}

group = "dev.junsung"
version = "0.2.0"

allOpen {
    annotation("org.springframework.context.annotation.Configuration")
}

java {
    withJavadocJar()
    withSourcesJar()
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

repositories {
    mavenCentral()
}

dependencies {
    // spring boot
    implementation("org.springframework.boot:spring-boot-autoconfigure:3.5.0")

    // spring security
    implementation("org.springframework.security:spring-security-config:6.5.0")
    implementation("org.springframework.security:spring-security-oauth2-jose:6.5.0")
    implementation("org.springframework.security:spring-security-web:6.5.0")

    // jackson
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.19.0")

    // jakarta
    implementation("jakarta.servlet:jakarta.servlet-api:6.1.0")

    // log4j
    implementation("org.slf4j:slf4j-api:2.0.17")

    // exception
    implementation("dev.junsung:exception:0.0.4")
}

kotlin {
    compilerOptions {
        freeCompilerArgs.addAll("-Xjsr305=strict")
    }
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            groupId = project.group.toString()
            artifactId = project.name
            version = project.version.toString()
            from(components["java"])
            pom {
                name.set("JWT Authorization Spring Boot Starter")
                description.set(
                    "The \"JWT Authorization Spring Boot Starter\" is designed to simplify the implementation of JSON Web Token (JWT) based authentication and authorization within Spring Boot applications. This starter provides a robust foundation for developers looking to secure their Spring Boot applications using JWT, a widely adopted industry standard for token-based authentication.",
                )
                url.set("https://github.com/junsung-cho/jwt-auth-spring-boot-starter")
                licenses {
                    license {
                        name.set("MIT License")
                        url.set("https://github.com/junsung-cho/jwt-auth-spring-boot-starter/blob/main/LICENSE")
                    }
                }
                scm {
                    url.set("https://github.com/junsung-cho/jwt-auth-spring-boot-starter.git")
                }
                developers {
                    developer {
                        id.set("junsung")
                        name.set("Junsung Cho")
                        email.set("junsung.dev@gmail.com")
                    }
                }
            }
        }
    }
    repositories {
        mavenLocal()
    }
}

signing {
    sign(publishing.publications)
}
