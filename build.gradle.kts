plugins {
    id("java")
    id("com.gradleup.shadow") version "8.3.5"
}

group = "com.tk.jwtinspector"
version = "1.0.0"

repositories {
    mavenCentral()
}

dependencies {
    // Burp Montoya API — provided at runtime by Burp itself, not bundled
    compileOnly("net.portswigger.burp.extensions:montoya-api:2024.12")

    // JWT parsing — handles malformed tokens better than jjwt
    implementation("com.nimbusds:nimbus-jose-jwt:10.0.2")

    // Test depedencies and platform
    testImplementation("org.junit.jupiter:junit-jupiter:5.11.3")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

tasks.test{
    useJUnitPlatform()
}

tasks.shadowJar {
    archiveBaseName.set("jwt-inspector")
    archiveClassifier.set("")
    manifest {
        attributes("Implementation-Version" to project.version)
    }
}

tasks.jar {
    enabled = false
}

tasks.build {
    dependsOn(tasks.shadowJar)
}
