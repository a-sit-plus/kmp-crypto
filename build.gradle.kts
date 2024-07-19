import org.jetbrains.dokka.gradle.DokkaMultiModuleTask

plugins {
    id("at.asitplus.gradle.conventions") version "2.0.0+20240619"
    id("com.android.library") version "8.2.0" apply (false)
}
group = "at.asitplus.crypto"


//access dokka plugin from conventions plugin's classpath in root project → no need to specify version
apply(plugin = "org.jetbrains.dokka")
tasks.getByName("dokkaHtmlMultiModule") {
    (this as DokkaMultiModuleTask)
    outputDirectory.set(File("${buildDir}/dokka"))
    includes.from("README.md")
    moduleName.set("KMP Crypto")
}

allprojects {
    apply(plugin = "org.jetbrains.dokka")
    group = rootProject.group
}
