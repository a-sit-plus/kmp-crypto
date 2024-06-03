pluginManagement {
    includeBuild("swift-klib-plugin")
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
        maven {
            url = uri("https://raw.githubusercontent.com/a-sit-plus/gradle-conventions-plugin/mvn/repo")
            name = "aspConventions"
        }
    }
}

dependencyResolutionManagement {
    repositories {
        google()
    }
}

include(":datatypes")
include(":datatypes-jws")
include(":datatypes-cose")
include(":provider")
rootProject.name = "kmp-crypto"