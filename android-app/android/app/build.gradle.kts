plugins {
    id("com.android.application")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

android {
    namespace = "io.github.futpib.zondd_control"
    compileSdk = flutter.compileSdkVersion
    ndkVersion = "28.2.13676358"

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    defaultConfig {
        applicationId = "io.github.futpib.zondd_control"
        minSdk = flutter.minSdkVersion
        ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
        targetSdk = flutter.targetSdkVersion
        versionCode = flutter.versionCode
        versionName = flutter.versionName
    }

    buildTypes {
        release {
            // Development signing only; supply a release key before publishing.
            signingConfig = signingConfigs.getByName("debug")
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17
    }
}

flutter {
    source = "../.."
}

val buildIrohTransport by tasks.registering(Exec::class) {
    workingDir = file("../..")
    commandLine("bash", "scripts/build-native.sh")
}
tasks.named("preBuild") { dependsOn(buildIrohTransport) }

repositories {
    maven { url = uri("https://github.com/rustls/rustls-platform-verifier/raw/maven-archive/android-release-support/maven/") }
}

// Keep the JVM verifier matched to the Rust dependency in the committed lockfile.
val verifierLock = file("../../native/Cargo.lock").readText()
val verifierVersion = Regex("name = \"rustls-platform-verifier-android\"\\nversion = \"([^\"]+)\"")
    .find(verifierLock)?.groupValues?.get(1) ?: error("Missing Rust Android verifier dependency")
dependencies { implementation("org.rustls:rustls-platform-verifier:$verifierVersion") }
