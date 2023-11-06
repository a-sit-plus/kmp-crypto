import DatatypeVersions.encoding
import DatatypeVersions.kmmresult
import DatatypeVersions.okio
import at.asitplus.gradle.*

plugins {
    kotlin("multiplatform")
    kotlin("plugin.serialization")
    id("signing")
    id("at.asitplus.gradle.conventions")
}

version = "2.1.0-SNAPSHOT"

kotlin {
    jvm()
    iosArm64()
    iosSimulatorArm64()
    iosX64()
    sourceSets {
        commonMain {
            dependencies {
                api(project(":datatypes"))
                implementation("com.squareup.okio:okio:${okio}")
                implementation(napier())
                implementation("io.matthewnelson.kotlin-components:encoding-base16:${encoding}")
                implementation("io.matthewnelson.kotlin-components:encoding-base64:${encoding}")
            }
        }

        commonTest {
            dependencies {
                implementation(kotlin("reflect"))
            }
        }
    }
}
exportIosFramework("KmpCryptoJws", serialization("json"), datetime(), project(":datatypes"))


val javadocJar = setupDokka(baseUrl = "https://github.com/a-sit-plus/kmp-crypto/tree/main/", multiModuleDoc = true)


publishing {
    publications {
        withType<MavenPublication> {
            artifact(javadocJar)
            pom {
                name.set("KMP Crypto Datatypes - JWS Addons")
                description.set("Kotlin Multiplatform Crypto Library - JWS Addons")
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
