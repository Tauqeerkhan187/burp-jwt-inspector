plugins {
    id("java")
    id("com.gradleup.shadow") version "8.3.5"
}

group = "com.tk.jwtinspector"
version = "0.3.5"

repositories {
    mavenCentral()
}

dependencies {
    // Burp Montoya API — provided at runtime by Burp itself, not bundled
    compileOnly("net.portswigger.burp.extensions:montoya-api:2024.12")

    // JWT parsing — handles malformed tokens better than jjwt
    implementation("com.nimbusds:nimbus-jose-jwt:10.0.2")
}

java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

tasks.shadowJar {
    archiveClassifier.set("")
    archiveBaseName.set("burp-jwt-inspector")
}

tasks.build {
    dependsOn(tasks.shadowJar)
}