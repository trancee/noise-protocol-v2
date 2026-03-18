import java.io.ByteArrayOutputStream
import java.io.FileInputStream
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.MessageDigest
import java.time.Duration
import java.util.Base64
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

plugins {
    kotlin("jvm") version "2.2.0"
    `maven-publish`
    signing
    id("org.jetbrains.dokka") version "2.0.0"
}

group = "noise.protocol"
version = providers.environmentVariable("RELEASE_VERSION")
    .orElse(providers.gradleProperty("releaseVersion"))
    .getOrElse("0.1.0-SNAPSHOT")

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.11.4")
}

tasks.test {
    useJUnitPlatform()

    val benchmarkPath = layout.buildDirectory.file("benchmarks/baseline-kotlin.json").get().asFile.absolutePath

    doLast {
        val file = File(benchmarkPath)
        if (!file.exists()) return@doLast

        val json = file.readText()
        val regex = Regex(""""name"\s*:\s*"([^"]+)"[^}]*"opsPerSec"\s*:\s*([\d.E+-]+)[^}]*"avgNs"\s*:\s*([\d.E+-]+)""")
        val matches = regex.findAll(json).toList()
        if (matches.isEmpty()) return@doLast

        val names = matches.map { it.groupValues[1] }
        val ops = matches.map { it.groupValues[2].toDouble() }
        val avgs = matches.map { it.groupValues[3].toDouble() }

        fun fmtLatency(ns: Double): String = when {
            ns < 1_000 -> "${ns.toLong()} ns"
            ns < 1_000_000 -> "${"%.1f".format(ns / 1_000)} µs"
            else -> "${"%.1f".format(ns / 1_000_000)} ms"
        }

        val nameW = maxOf(names.maxOf { it.length }, 9)
        println("\n⚡ Kotlin Benchmark Results\n")
        println("| ${"Benchmark".padEnd(nameW)} |    ops/sec |  avg latency |")
        println("|${"".padEnd(nameW + 2, '-')}|-----------:|-------------:|")
        for (i in names.indices) {
            println("| ${names[i].padEnd(nameW)} | %10d | %12s |".format(ops[i].toLong(), fmtLatency(avgs[i])))
        }
        println()
    }
}

kotlin {
    jvmToolchain(21)
}

// Generate sources JAR for publishing
val sourcesJar by tasks.registering(Jar::class) {
    archiveClassifier.set("sources")
    from(sourceSets.main.get().allSource)
}

// Generate Javadoc JAR from Dokka
val javadocJar by tasks.registering(Jar::class) {
    archiveClassifier.set("javadoc")
    dependsOn(tasks.named("dokkaGeneratePublicationHtml"))
    from(layout.buildDirectory.dir("dokka/html"))
}

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            from(components["java"])
            artifact(sourcesJar)
            artifact(javadocJar)

            pom {
                name.set("Noise Protocol")
                description.set("Pure Kotlin implementation of the Noise Protocol Framework (RFC-like) with zero external dependencies.")
                url.set("https://github.com/trancee/noise-protocol-v2")

                licenses {
                    license {
                        name.set("The Unlicense")
                        url.set("https://unlicense.org")
                    }
                }

                developers {
                    developer {
                        id.set("trancee")
                        name.set("trancee")
                        url.set("https://github.com/trancee")
                    }
                }

                scm {
                    url.set("https://github.com/trancee/noise-protocol-v2")
                    connection.set("scm:git:git://github.com/trancee/noise-protocol-v2.git")
                    developerConnection.set("scm:git:ssh://github.com/trancee/noise-protocol-v2.git")
                }
            }
        }
    }

    repositories {
        // GitHub Packages
        maven {
            name = "GitHubPackages"
            url = uri("https://maven.pkg.github.com/trancee/noise-protocol-v2")
            credentials {
                username = project.findProperty("gpr.user") as String? ?: System.getenv("GITHUB_ACTOR")
                password = project.findProperty("gpr.key") as String? ?: System.getenv("GITHUB_TOKEN")
            }
        }

        // Local staging directory (used by publishToMavenCentral task)
        maven {
            name = "staging"
            url = uri(layout.buildDirectory.dir("staging-deploy"))
        }
    }
}

// Signing (required for Maven Central, optional for GitHub Packages)
signing {
    isRequired = !version.toString().endsWith("SNAPSHOT")
    val signingKey: String? by project
    val signingPassword: String? by project
    if (signingKey != null) {
        useInMemoryPgpKeys(signingKey, signingPassword)
    }
    sign(publishing.publications["mavenJava"])
}

// ── Maven Central Portal publishing (zero third-party plugin dependencies) ──

tasks.register("publishToMavenCentral") {
    description = "Publish artifacts to Maven Central via the Portal API"
    group = "publishing"

    dependsOn("publishMavenJavaPublicationToStagingRepository")

    val stagingPath = layout.buildDirectory.dir("staging-deploy").get().asFile.absolutePath
    val bundlePath = layout.buildDirectory.file("central-bundle.zip").get().asFile.absolutePath
    val projectGroup = project.group.toString()
    val projectName = project.name
    val projectVersion = project.version.toString()

    doLast {
        val stagingDir = File(stagingPath)
        val bundleFile = File(bundlePath)

        val username = providers.environmentVariable("MAVEN_CENTRAL_USERNAME")
            .orElse(providers.gradleProperty("mavenCentralUsername"))
            .orNull ?: error("MAVEN_CENTRAL_USERNAME not set")
        val password = providers.environmentVariable("MAVEN_CENTRAL_PASSWORD")
            .orElse(providers.gradleProperty("mavenCentralPassword"))
            .orNull ?: error("MAVEN_CENTRAL_PASSWORD not set")

        val autoPublish = providers.environmentVariable("MAVEN_CENTRAL_AUTO_PUBLISH")
            .orElse(providers.gradleProperty("mavenCentralAutoPublish"))
            .orElse("false")
            .get().toBoolean()

        logger.lifecycle("Generating checksums...")
        generateChecksums(stagingDir)

        logger.lifecycle("Creating bundle: ${bundleFile.name}")
        createBundle(stagingDir, bundleFile)

        val token = Base64.getEncoder().encodeToString("$username:$password".toByteArray())
        val publishingType = if (autoPublish) "AUTOMATIC" else "USER_MANAGED"
        val deploymentName = "$projectGroup:$projectName:$projectVersion"

        logger.lifecycle("Uploading bundle to Central Portal...")
        val deploymentId = uploadBundle(bundleFile, token, publishingType, deploymentName)
        logger.lifecycle("Upload complete. Deployment ID: $deploymentId")

        logger.lifecycle("Waiting for validation...")
        waitForValidation(deploymentId, token, waitForPublishing = autoPublish)

        if (autoPublish) {
            logger.lifecycle("Deployment published to Maven Central!")
        } else {
            logger.lifecycle("Deployment validated. Publish manually at https://central.sonatype.com/publishing/deployments")
        }

        bundleFile.delete()
    }
}

// ── Helper functions for Maven Central publishing ──

fun generateChecksums(dir: File) {
    dir.walkTopDown()
        .filter { it.isFile && !it.name.endsWith(".md5") && !it.name.endsWith(".sha1")
            && !it.name.endsWith(".sha256") && !it.name.endsWith(".sha512")
            && !it.name.startsWith("maven-metadata") }
        .forEach { file ->
            writeChecksum(file, "MD5", ".md5")
            writeChecksum(file, "SHA-1", ".sha1")
        }
}

fun writeChecksum(file: File, algorithm: String, extension: String) {
    val digest = MessageDigest.getInstance(algorithm)
    file.inputStream().use { input ->
        val buffer = ByteArray(8192)
        var bytesRead: Int
        while (input.read(buffer).also { bytesRead = it } != -1) {
            digest.update(buffer, 0, bytesRead)
        }
    }
    val hex = digest.digest().joinToString("") { "%02x".format(it) }
    File(file.absolutePath + extension).writeText(hex)
}

fun createBundle(stagingDir: File, outputFile: File) {
    ZipOutputStream(outputFile.outputStream()).use { zos ->
        stagingDir.walkTopDown()
            .filter { it.isFile && !it.name.startsWith("maven-metadata") }
            .forEach { file ->
                val entryPath = file.relativeTo(stagingDir).path
                zos.putNextEntry(ZipEntry(entryPath))
                file.inputStream().use { it.copyTo(zos) }
                zos.closeEntry()
            }
    }
}

fun uploadBundle(bundleFile: File, token: String, publishingType: String, name: String): String {
    val boundary = "----FormBoundary${System.currentTimeMillis()}"
    val body = buildMultipartBody(boundary, bundleFile)

    val request = HttpRequest.newBuilder()
        .uri(URI.create(
            "https://central.sonatype.com/api/v1/publisher/upload" +
            "?publishingType=$publishingType" +
            "&name=${URLEncoder.encode(name, Charsets.UTF_8)}"
        ))
        .header("Authorization", "Bearer $token")
        .header("Content-Type", "multipart/form-data; boundary=$boundary")
        .POST(HttpRequest.BodyPublishers.ofByteArray(body))
        .build()

    val client = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(60))
        .build()
    val response = client.send(request, HttpResponse.BodyHandlers.ofString())

    if (response.statusCode() != 201) {
        error("Upload failed (${response.statusCode()}): ${response.body()}")
    }

    return response.body().trim()
}

fun buildMultipartBody(boundary: String, file: File): ByteArray {
    val output = ByteArrayOutputStream()
    output.write("--$boundary\r\n".toByteArray())
    output.write("Content-Disposition: form-data; name=\"bundle\"; filename=\"${file.name}\"\r\n".toByteArray())
    output.write("Content-Type: application/octet-stream\r\n".toByteArray())
    output.write("\r\n".toByteArray())
    FileInputStream(file).use { it.copyTo(output) }
    output.write("\r\n".toByteArray())
    output.write("--$boundary--\r\n".toByteArray())
    return output.toByteArray()
}

fun waitForValidation(deploymentId: String, token: String, waitForPublishing: Boolean) {
    val client = HttpClient.newHttpClient()
    val maxWaitMs = 30 * 60 * 1000L
    val pollIntervalMs = 5_000L
    val start = System.currentTimeMillis()

    while (System.currentTimeMillis() - start < maxWaitMs) {
        val request = HttpRequest.newBuilder()
            .uri(URI.create("https://central.sonatype.com/api/v1/publisher/status?id=$deploymentId"))
            .header("Authorization", "Bearer $token")
            .POST(HttpRequest.BodyPublishers.noBody())
            .build()

        val response = client.send(request, HttpResponse.BodyHandlers.ofString())
        if (response.statusCode() != 200) {
            error("Status check failed (${response.statusCode()}): ${response.body()}")
        }

        val body = response.body()
        val state = Regex("\"deploymentState\"\\s*:\\s*\"([A-Z_]+)\"").find(body)?.groupValues?.get(1)
        if (state == null) {
            logger.warn("Could not parse deploymentState from: $body")
            Thread.sleep(pollIntervalMs)
            continue
        }

        when (state) {
            "PENDING", "VALIDATING" -> logger.lifecycle("  Status: $state ...")
            "VALIDATED" -> {
                if (!waitForPublishing) return
                logger.lifecycle("  Status: VALIDATED, waiting for publishing...")
            }
            "PUBLISHING" -> logger.lifecycle("  Status: PUBLISHING...")
            "PUBLISHED" -> return
            "FAILED" -> {
                val errors = Regex("\"errors\"\\s*:\\s*\\{([^}]+)\\}").find(body)?.groupValues?.get(1) ?: ""
                val errorMsg = if (errors.isNotBlank()) "\nValidation errors:\n$errors" else ""
                error("Deployment FAILED.$errorMsg\nFull response: $body")
            }
            else -> logger.warn("  Unknown state: $state")
        }

        Thread.sleep(pollIntervalMs)
    }

    error("Timed out waiting for deployment validation after ${maxWaitMs / 1000}s")
}
