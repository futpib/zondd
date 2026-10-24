package io.github.futpib.zondd_control

import android.content.Context
import android.os.Bundle
import androidx.core.content.pm.PackageInfoCompat
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

class MainActivity : FlutterActivity() {
    private var credentialVault: CredentialVault? = null
    private external fun initVerifier(context: Context)

    override fun onCreate(savedInstanceState: Bundle?) {
        System.loadLibrary("zondd_android_transport")
        initVerifier(applicationContext)
        super.onCreate(savedInstanceState)
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        credentialVault = CredentialVault(this)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "io.github.futpib.zond/credential_vault")
            .setMethodCallHandler(credentialVault)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "io.github.futpib.zond/app_info")
            .setMethodCallHandler { call, result ->
                if (call.method == "version") {
                    val info = packageManager.getPackageInfo(packageName, 0)
                    result.success("${info.versionName}+${PackageInfoCompat.getLongVersionCode(info)}")
                } else {
                    result.notImplemented()
                }
            }
    }

    override fun onStop() {
        credentialVault?.cancelPending()
        super.onStop()
    }

}
