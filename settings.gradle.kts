pluginManagement {
    repositories {
        mavenCentral()
        gradlePluginPortal()
        maven {
            url = uri("https://raw.githubusercontent.com/a-sit-plus/gradle-conventions-plugin/mvn/repo")
            name = "aspConventions"
        }
    }
}

include(":datatypes")
include(":datatypes-jws")
include(":datatypes-cose")
rootProject.name = "kmp-crypto"