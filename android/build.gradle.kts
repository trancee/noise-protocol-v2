plugins {
    kotlin("jvm") version "2.2.0"
    `maven-publish`
    signing
    id("org.jetbrains.dokka") version "2.0.0"
}

group = "noise.protocol"
version = "0.1.0-SNAPSHOT"

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

        // Maven Central via Sonatype OSSRH
        maven {
            name = "OSSRH"
            val releasesUrl = uri("https://s01.oss.sonatype.org/service/local/staging/deploy/maven2/")
            val snapshotsUrl = uri("https://s01.oss.sonatype.org/content/repositories/snapshots/")
            url = if (version.toString().endsWith("SNAPSHOT")) snapshotsUrl else releasesUrl
            credentials {
                username = project.findProperty("ossrh.username") as String? ?: System.getenv("OSSRH_USERNAME")
                password = project.findProperty("ossrh.password") as String? ?: System.getenv("OSSRH_PASSWORD")
            }
        }
    }
}

// Signing (required for Maven Central, optional for GitHub Packages)
signing {
    isRequired = !version.toString().endsWith("SNAPSHOT")
    sign(publishing.publications["mavenJava"])
}
