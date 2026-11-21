plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

val neteyeVersion = (project.findProperty("neteyeVersion") as String?) ?: "0.1.0"
val verParts = neteyeVersion.split(".").mapNotNull { it.toIntOrNull() }
val computedVersionCode = (verParts.getOrElse(0) { 0 } * 10000) +
    (verParts.getOrElse(1) { 1 } * 100) +
    verParts.getOrElse(2) { 0 }

android {
    namespace = "com.neteye.sensor"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.neteye.sensor"
        minSdk = 26
        targetSdk = 34
        versionCode = maxOf(1, computedVersionCode)
        versionName = neteyeVersion

        ndk {
            abiFilters += listOf("arm64-v8a")
        }
    }

    val keystorePath = System.getenv("ANDROID_KEYSTORE_PATH")
    signingConfigs {
        if (!keystorePath.isNullOrBlank() && file(keystorePath).exists()) {
            create("release") {
                storeFile = file(keystorePath)
                storePassword = System.getenv("ANDROID_KEYSTORE_PASSWORD") ?: ""
                keyAlias = System.getenv("ANDROID_KEY_ALIAS") ?: ""
                keyPassword = System.getenv("ANDROID_KEY_PASSWORD") ?: ""
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = if (signingConfigs.findByName("release") != null) {
                signingConfigs.getByName("release")
            } else {
                signingConfigs.getByName("debug")
            }
        }
        debug {
            isMinifyEnabled = false
        }
    }

    androidResources {
        noCompress += listOf("bin")
    }

    packaging {
        jniLibs {
            // Required on Android 10+ so libneteye.so & libbangdb.so are extracted to nativeLibraryDir and executable.
            useLegacyPackaging = true
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
}
