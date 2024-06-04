import at.asitplus.gradle.coroutines
import at.asitplus.gradle.napier
import at.asitplus.gradle.datetime
import at.asitplus.gradle.exportIosFramework
import at.asitplus.gradle.kmmresult
import at.asitplus.gradle.serialization
import at.asitplus.gradle.setupDokka


plugins {
    id("com.android.library")
    kotlin("multiplatform")
    kotlin("plugin.serialization")
    id("org.jetbrains.dokka")
    id("signing")
    id("io.github.ttypic.swiftklib") version "0.5.2"
    id("at.asitplus.gradle.conventions")
}


val kmp_crypto: String by project


version = "0.0.2-SNAPSHOT"

kotlin {
    jvm()
    androidTarget {
        publishLibraryVariants("release")
    }
    listOf(
        iosX64(),
        iosArm64(),
        iosSimulatorArm64(),
    ).forEach { iosTarget -> //Hella inefficient, but reliable
        iosTarget.compilations.getByName("main") {
            cinterops {
                create("Krypto")
            }
        }
    }
    sourceSets.commonMain.dependencies {
        implementation(coroutines())
        implementation(napier())
        api(project(":datatypes"))
        implementation(kotlincrypto.hash.sha2)
        implementation(kotlincrypto.secureRandom)
    }
    sourceSets.androidMain.dependencies {
        implementation("androidx.biometric:biometric:1.2.0-alpha05")
    }
}

swiftklib {
    create("Krypto") {
        minIos = 14
        path = file("src/swift")
        packageName("at.asitplus.swift.krypto")
    }
}

android {
    namespace = "at.asitplus.crypto.android"
    compileSdk = 34
    defaultConfig {
        minSdk = 33
    }
}

exportIosFramework(
    "KmpCryptoProvider",
    serialization("json"),
    datetime(),
    kmmresult(),
    project(":datatypes"),
    libs.bignum
)

val javadocJar = setupDokka(
    baseUrl = "https://github.com/a-sit-plus/kmp-crypto/tree/main/",
    multiModuleDoc = true
)


publishing {
    publications {
        withType<MavenPublication> {
            artifact(javadocJar)
            pom {
                name.set("KMP Crypto Provider")
                description.set("Kotlin Multiplatform Crypto Provider")
                url.set("https://github.com/a-sit-plus/kmp-crypto")
                licenses {
                    license {
                        name.set("The Apache License, Version 2.0")
                        url.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
                    }
                }
                developers {
                    developer {
                        id.set("JesusMcCloud")
                        name.set("Bernd Prünster")
                        email.set("bernd.pruenster@a-sit.at")
                    }
                    developer {
                        id.set("nodh")
                        name.set("Christian Kollmann")
                        email.set("christian.kollmann@a-sit.at")
                    }
                }
                scm {
                    connection.set("scm:git:git@github.com:a-sit-plus/kmp-crypto.git")
                    developerConnection.set("scm:git:git@github.com:a-sit-plus/kmp-crypto.git")
                    url.set("https://github.com/a-sit-plus/kmp-crypto")
                }
            }
        }
    }
    repositories {
        mavenLocal {
            signing.isRequired = false
        }
        maven {
            url = uri(layout.projectDirectory.dir("..").dir("repo"))
            name = "local"
            signing.isRequired = false
        }
    }
}

signing {
    val signingKeyId: String? by project
    val signingKey: String? by project
    val signingPassword: String? by project
    useInMemoryPgpKeys(signingKeyId, signingKey, signingPassword)
    sign(publishing.publications)
}
