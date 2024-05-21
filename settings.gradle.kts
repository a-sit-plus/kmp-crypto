pluginManagement {
    pluginManagement {
        includeBuild("gradle-conventions-plugin")
        repositories {
            google()
            gradlePluginPortal()
            mavenCentral()
        }
    }
}

include(":datatypes")
include(":datatypes-jws")
include(":datatypes-cose")
rootProject.name = "kmp-crypto"
