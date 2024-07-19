plugins {
    alias(libs.plugins.multiplatform).apply(false)
    alias(libs.plugins.compose).apply(false)
    alias(libs.plugins.android.application).apply(false)
    alias(libs.plugins.buildConfig).apply(false)
 //   id("at.asitplus.gradle.conventions") version "1.9.23+20240319+1"
}

allprojects {
    repositories {
        maven(rootProject.projectDir.absolutePath+"/kmp-crypto/repo")
        maven(uri("https://raw.githubusercontent.com/a-sit-plus/kotlinx.serialization/mvn/repo"))
        mavenCentral()
        google()
        maven {
            url = uri("https://oss.sonatype.org/content/repositories/snapshots")
            name = "bigNum"
        }
    }
}