plugins {
    id("maven-publish")
    id("signing")
    kotlin("jvm") version "1.9.23"
    kotlin("plugin.allopen") version "1.9.23"
}

group = "dev.junsung"
version = "0.0.2"

allOpen {
    annotation("org.springframework.context.annotation.Configuration")
}

java {
    withJavadocJar()
    withSourcesJar()
}

repositories {
    mavenCentral()
}

dependencies {
    // spring boot
    implementation("org.springframework.boot:spring-boot-autoconfigure:3.2.3")

    // spring security
    implementation("org.springframework.security:spring-security-config:6.2.2")
    implementation("org.springframework.security:spring-security-oauth2-jose:6.2.2")
    implementation("org.springframework.security:spring-security-web:6.2.2")

    // jackson
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.16.1")

    // jakarta
    implementation("jakarta.servlet:jakarta.servlet-api:6.1.0-M2")

    // log4j
    implementation("org.slf4j:slf4j-api:2.0.9")
}

kotlin {
    jvmToolchain(21)
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
                description.set("The \"JWT Authorization Spring Boot Starter\" is designed to simplify the implementation of JSON Web Token (JWT) based authentication and authorization within Spring Boot applications. This starter provides a robust foundation for developers looking to secure their Spring Boot applications using JWT, a widely adopted industry standard for token-based authentication.")
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
        maven {
            val username = System.getenv("OSSRH_USERNAME")
            val password = System.getenv("OSSRH_PASSWORD")

            setUrl("https://s01.oss.sonatype.org/service/local/staging/deploy/maven2/")
            credentials {
                this.username = username
                this.password = password
            }
        }
    }
}

signing {
    sign(publishing.publications)
}
