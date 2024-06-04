import at.asitplus.gradle.*
import com.squareup.kotlinpoet.ClassName
import com.squareup.kotlinpoet.FileSpec
import com.squareup.kotlinpoet.PropertySpec
import com.squareup.kotlinpoet.TypeSpec
import java.io.FileInputStream
import java.util.regex.Pattern


buildscript {
    dependencies {
        classpath(libs.kotlinpoet)
    }
}

plugins {
    kotlin("multiplatform")
    kotlin("plugin.serialization")
    id("signing")
    id("at.asitplus.gradle.conventions")
}

val artifactVersion: String by extra
version = artifactVersion


private val Pair<*, String?>.comment: String? get() = this.second
private val Pair<String, *>.oid: String? get() = this.first

//generate Known OIDs when importing the project.
//This is dirt-cheap, so it does not matter that this call is hardcoded here
generateKnowOIDs()

//Also create a task that regenerates known OIDs, should this be needed
tasks.register<DefaultTask>("regenerateKnownOIDs") {
    doFirst { generateKnowOIDs() }
}

/**
 * Generates `KnownOIDs.kt` containing an object of the same name
 * in generated/commonMain/kotlin/at/asitplus/crypto/datatypes/asn1.
 *
 * This object contains the contents declared in src/commonMain/resources/dumpasn1.cfg,
 * which is taken from Peter Gutmann's [dumpasn1](https://www.cs.auckland.ac.nz/~pgut001/dumpasn1.cfg).
 *
 * Internally, it iterates over the config file, collecting a tuple of OID, Description and optional Comment.
 * When the next OID is encountered, the previously collected tuple ist added to a map
 * (the Description is used as key, since this corresponds to what is colloquially referred to as attribute name).
 * Due to Descriptions not being Unique, conflicts can arise.
 * In that case, a new key is created as `Description||_||OID`.
 * <br>
 * Finally, some basic normalisation happens, since some Descriptions contain characters not allowed for Kotlin identifiers
 * and malformed (deprecated OIDs) are stripped.
 *
 * Once the collection phase is finished, KotlinPoet is used to generate the actual Kotlin source.
 *
 * `# End of Fahnenstange`
 */
fun generateKnowOIDs() {
    logger.lifecycle("  Regenerating KnownOIDs.kt")
    val collected = mutableMapOf<String, Pair<String, String?>>()


    var oid: String? = null
    var comment: String? = null
    var description: String? = null

    FileInputStream(
        project.layout.projectDirectory.dir("src").dir("commonMain")
            .dir("resources").file("dumpasn1.cfg").asFile
    ).reader().forEachLine { line ->
        if (!(line.isBlank() || line.startsWith("#"))) {
            //we know a new OID
            if (line.startsWith("OID = ")) {
                val newOID = line.substring("OID = ".length).trim()
                // we know the previously declared OID was fully read
                if (oid != null) {
                    //filter iffy stuff
                    val segments = oid!!.split(Pattern.compile("\\s"))
                    if (segments.size > 1 && segments[1].toUInt() > 39u)
                        logger.warn("w: Skipping OID $oid $description ($comment)")
                    else {
                        //if we collected the name of this OID already, we need to assign a new name
                        collected[description]?.also { _ ->
                            collected["${description}_${
                                oid!!.replace(" ", "_")
                            }"] = Pair(oid!!, comment)
                        } ?: run {
                            //if it is still new, we can just add it
                            collected[description!!] = Pair(oid!!, comment)
                        }
                    }
                }
                oid = newOID
                description = null
                comment = null
            } else if (line.startsWith("Description = ")) {
                description = line.substring("Description = ".length).trim()
                    .replace("?", "")
                    .replace("(", "")
                    .replace(")", "")
                    .replace("#", "")
                    .replace("\"", "")
                    .replace(' ', '_')
                    .replace('-', '_')
                    .replace(",", "").let {
                        it.ifBlank { oid!!.replace(" ", "_") }
                    }
            } else if (line.startsWith("Comment = ")) {
                comment = line.substring("Comment = ".length).trim()
            }
        }
    }

    val file =
        FileSpec.builder("at.asitplus.crypto.datatypes.asn1", "KnownOIDs")
            .addType(
                TypeSpec.objectBuilder("KnownOIDs").apply {
                    collected.toList()
                        .distinctBy { (_, oidTriple) -> oidTriple.oid }
                        .sortedBy { (name, _) -> name }
                        .forEach { (name, oidTriple) ->
                            addProperty(
                                PropertySpec.builder(
                                    name,
                                    ClassName(
                                        packageName = "at.asitplus.crypto.datatypes.asn1",
                                        "ObjectIdentifier"
                                    )
                                )
                                    .initializer("\nObjectIdentifier(\n\"${oidTriple.oid!!}\"\n)")
                                    .addKdoc(
                                        "`${
                                            oidTriple.oid!!.replace(
                                                ' ',
                                                '.'
                                            )
                                        }`: ${oidTriple.comment}"
                                    )
                                    .build()
                            )
                        }

                }.build()
            ).build()

    file.writeTo(
        project.layout.projectDirectory.dir("generated").dir("commonMain")
            .dir("kotlin").asFile
    )

}



kotlin {
    jvm()
    iosArm64()
    iosSimulatorArm64()
    iosX64()

    sourceSets {
        all {
            languageSettings.optIn("kotlin.ExperimentalUnsignedTypes")
        }

        commonMain {
            kotlin.srcDir(
                project.layout.projectDirectory.dir("generated")
                    .dir("commonMain").dir("kotlin")
            )

            dependencies {
                api(kmmresult())
                api(serialization("json"))
                api(datetime())
                implementation(libs.base16)
                implementation(libs.base64)
                api(libs.bignum)
            }
        }

        commonTest {
            dependencies {
                implementation(kotest("property"))
            }
        }

        jvmMain {
            dependencies {
                api(bouncycastle("bcpkix"))
                api(coroutines("jvm"))
            }
        }

    }
}

exportIosFramework(
    "KmpCrypto",
    serialization("json"),
    datetime(),
    kmmresult(),
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
                name.set("KMP Crypto Datatypes")
                description.set("Kotlin Multiplatform Crypto Core Library, Datatypes and ASN.1 Perser+Encoder")
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
