package com.redeye.agent.installedapps

import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import android.view.accessibility.AccessibilityManager
import android.accessibilityservice.AccessibilityServiceInfo
import android.app.AppOpsManager
import android.content.Context
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import java.security.MessageDigest
import java.lang.StringBuilder

class InstalledAppsModule : Module() {
  override fun definition() = ModuleDefinition {
    Name("InstalledApps")

    Function("getAppCount") {
      val context = appContext.reactContext ?: return@Function 0
      val pm = context.packageManager
      try {
        pm.getInstalledPackages(0).size
      } catch (e: Exception) {
        0
      }
    }

    Function("getInstalledApps") {
      val context = appContext.reactContext ?: return@Function emptyList<Map<String, Any>>()
      val pm = context.packageManager
      
      val am = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as? AccessibilityManager
      val installedAccessibilityServices = am?.installedAccessibilityServiceList ?: emptyList<AccessibilityServiceInfo>()
      val enabledAccessibilityServices = am?.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK) ?: emptyList<AccessibilityServiceInfo>()
      
      val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as? DevicePolicyManager
      val activeAdmins = dpm?.activeAdmins ?: emptyList<ComponentName>()
      
      val accessibilityMap = mutableMapOf<String, MutableList<AccessibilityServiceInfo>>()
      for (info in installedAccessibilityServices) {
        val sInfo = info.resolveInfo?.serviceInfo ?: continue
        val pkg = sInfo.packageName ?: continue
        if (!accessibilityMap.containsKey(pkg)) {
          accessibilityMap[pkg] = mutableListOf()
        }
        accessibilityMap[pkg]?.add(info)
      }

      val packages = pm.getInstalledPackages(0)
      val list = mutableListOf<Map<String, Any>>()

      for (packageInfo in packages) {
        val appInfo = packageInfo.applicationInfo ?: continue
        val isSystem = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
        val appName = appInfo.loadLabel(pm).toString()
        val packageName = packageInfo.packageName
        val versionName = packageInfo.versionName ?: ""
        val versionCode = packageInfo.versionCode
        val installTime = packageInfo.firstInstallTime
        val updateTime = packageInfo.lastUpdateTime
        val enabled = appInfo.enabled
        val targetSdk = appInfo.targetSdkVersion

        // getInstallerPackageName can throw IllegalArgumentException on some OS versions
        var installer = ""
        try {
          installer = pm.getInstallerPackageName(packageName) ?: ""
        } catch (e: Exception) {
          // ignore
        }

        // Get certificate fingerprint
        val certificate = getCertificateFingerprint(pm, packageName)

        val apkPath = appInfo.sourceDir ?: ""
        var apkSha256 = "Unknown"
        if (apkPath.isNotEmpty()) {
          val cached = sha256Cache[packageName]
          if (cached != null && cached.first == updateTime) {
            apkSha256 = cached.second
          } else {
            apkSha256 = getApkSha256(apkPath)
            sha256Cache[packageName] = Pair(updateTime, apkSha256)
          }
        }
        val hasLauncher = pm.getLaunchIntentForPackage(packageName) != null

        // Get detailed package info for manifest analysis
        var requestedPermissions = emptyList<String>()
        var grantedPermissionsList = emptyList<String>()
        var pendingPermissionsList = emptyList<String>()
        var servicesList = emptyList<String>()
        var receiversList = emptyList<String>()
        var hasAccessibility = false
        var hasDeviceAdmin = false
        var hasForegroundService = false
        var hasOverlay = false
        var hasBootReceiver = false
        var exportedComponentsCount = 0
        var readSmsGranted = false
        var readContactsGranted = false
        var cameraGranted = false
        var recordAudioGranted = false
        var hasBatteryExemption = false
        var keyloggerDetected = false
        var persistenceScore = 0
        var deviceAdminActive = false
        var isDeviceOwner = false
        var isProfileOwner = false

        try {
          deviceAdminActive = activeAdmins.any { it.packageName == packageName }
          isDeviceOwner = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
            dpm?.isDeviceOwnerApp(packageName) ?: false
          } else {
            false
          }
          isProfileOwner = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            dpm?.isProfileOwnerApp(packageName) ?: false
          } else {
            false
          }

          val flags = PackageManager.GET_PERMISSIONS or
                      PackageManager.GET_SERVICES or
                      PackageManager.GET_RECEIVERS or
                      PackageManager.GET_ACTIVITIES or
                      PackageManager.GET_PROVIDERS

          val detailedInfo = pm.getPackageInfo(packageName, flags)

          // 1. Requested permissions
          requestedPermissions = detailedInfo.requestedPermissions?.toList() ?: emptyList()
          val gp = mutableListOf<String>()
          val pp = mutableListOf<String>()
          requestedPermissions.forEach { perm ->
            if (pm.checkPermission(perm, packageName) == PackageManager.PERMISSION_GRANTED) {
              gp.add(perm)
            } else {
              pp.add(perm)
            }
          }
          grantedPermissionsList = gp
          pendingPermissionsList = pp
          hasOverlay = requestedPermissions.contains("android.permission.SYSTEM_ALERT_WINDOW")
          hasBootReceiver = requestedPermissions.contains("android.permission.RECEIVE_BOOT_COMPLETED")
          hasForegroundService = requestedPermissions.any { it.startsWith("android.permission.FOREGROUND_SERVICE") }
          hasBatteryExemption = requestedPermissions.contains("android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS")

          // Check runtime permission grant statuses
          readSmsGranted = pm.checkPermission("android.permission.READ_SMS", packageName) == PackageManager.PERMISSION_GRANTED
          readContactsGranted = pm.checkPermission("android.permission.READ_CONTACTS", packageName) == PackageManager.PERMISSION_GRANTED
          cameraGranted = pm.checkPermission("android.permission.CAMERA", packageName) == PackageManager.PERMISSION_GRANTED
          recordAudioGranted = pm.checkPermission("android.permission.RECORD_AUDIO", packageName) == PackageManager.PERMISSION_GRANTED

          // 2. Services & Accessibility Service
          val services = detailedInfo.services
          if (services != null) {
            val listSvc = mutableListOf<String>()
            for (service in services) {
              listSvc.add(service.name)
              if ("android.permission.BIND_ACCESSIBILITY_SERVICE" == service.permission) {
                hasAccessibility = true
              }
              if (service.exported) {
                exportedComponentsCount++
              }
            }
            servicesList = listSvc
          }

          // 3. Receivers & Device Admin
          val receivers = detailedInfo.receivers
          if (receivers != null) {
            val listRec = mutableListOf<String>()
            for (receiver in receivers) {
              listRec.add(receiver.name)
              if ("android.permission.BIND_DEVICE_ADMIN" == receiver.permission) {
                hasDeviceAdmin = true
              }
              if (receiver.exported) {
                exportedComponentsCount++
              }
            }
            receiversList = listRec
          }

          // 4. Exported activities and providers
          detailedInfo.activities?.forEach { activity ->
            if (activity.exported) exportedComponentsCount++
          }
          detailedInfo.providers?.forEach { provider ->
            if (provider.exported) exportedComponentsCount++
          }

          keyloggerDetected = hasAccessibility

          // 5. Compute persistence score
          if (hasBootReceiver) persistenceScore++
          if (hasForegroundService) persistenceScore++
          if (hasBatteryExemption) persistenceScore++
          if (servicesList.isNotEmpty() || receiversList.isNotEmpty()) persistenceScore++

        } catch (e: Exception) {
          // Detailed info retrieval failed, fall back
        }

        var accessibilityServiceName = ""
        var accessibilityServiceEnabled = false
        val accessibilityCapabilities = mutableListOf<String>()
        var overlayGranted = false

        // Check accessibility service info
        val servicesForPkg = accessibilityMap[packageName]
        if (servicesForPkg != null && servicesForPkg.isNotEmpty()) {
          // Take the first matching accessibility service
          val serviceInfo = servicesForPkg.first()
          accessibilityServiceName = serviceInfo.resolveInfo?.serviceInfo?.name ?: ""
          
          // Check if enabled
          accessibilityServiceEnabled = enabledAccessibilityServices.any {
            it.resolveInfo?.serviceInfo?.packageName == packageName && it.resolveInfo?.serviceInfo?.name == accessibilityServiceName
          }

          // Inspect capabilities
          val cap = serviceInfo.capabilities
          if ((cap and AccessibilityServiceInfo.CAPABILITY_CAN_RETRIEVE_WINDOW_CONTENT) != 0) {
            accessibilityCapabilities.add("retrieve_window_content")
          }
          if ((cap and AccessibilityServiceInfo.CAPABILITY_CAN_REQUEST_TOUCH_EXPLORATION) != 0) {
            accessibilityCapabilities.add("touch_exploration")
          }
          if ((cap and AccessibilityServiceInfo.CAPABILITY_CAN_REQUEST_FILTER_KEY_EVENTS) != 0) {
            accessibilityCapabilities.add("filter_key_events")
          }
          if ((cap and AccessibilityServiceInfo.CAPABILITY_CAN_PERFORM_GESTURES) != 0) {
            accessibilityCapabilities.add("perform_gestures")
          }
          if (Build.VERSION.SDK_INT >= 30 && (cap and AccessibilityServiceInfo.CAPABILITY_CAN_TAKE_SCREENSHOT) != 0) {
            accessibilityCapabilities.add("take_screenshot")
          }
          if ((cap and AccessibilityServiceInfo.CAPABILITY_CAN_CONTROL_MAGNIFICATION) != 0) {
            accessibilityCapabilities.add("control_magnification")
          }
        }

        // Check overlay runtime permission status (using AppOpsManager checkOpNoThrow via reflection if needed or directly if possible)
        try {
          val appOps = context.getSystemService(Context.APP_OPS_SERVICE) as? AppOpsManager
          if (appOps != null) {
            val checkOpMethod = AppOpsManager::class.java.getMethod(
              "checkOpNoThrow",
              String::class.java,
              Int::class.java,
              String::class.java
            )
            val mode = checkOpMethod.invoke(
              appOps,
              "android:system_alert_window",
              appInfo.uid,
              packageName
            ) as? Int
            if (mode == AppOpsManager.MODE_ALLOWED) {
              overlayGranted = true
            }
          }
        } catch (e: Exception) {
          // fallback checks
          if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            try {
              // Note: Settings.canDrawOverlays(context) is only for our package, but checkOp is general.
              // If reflection fails, default to false.
            } catch (settingsErr: Exception) {}
          }
        }

        val map = mapOf(
          "app_name" to appName,
          "package_name" to packageName,
          "version_name" to versionName,
          "version_code" to versionCode,
          "install_time" to installTime,
          "update_time" to updateTime,
          "system_app" to isSystem,
          "enabled" to enabled,
          "installer" to installer,
          "target_sdk" to targetSdk,
          "certificate" to certificate,
          "apk_sha256" to apkSha256,
          "has_launcher" to hasLauncher,
          "requested_permissions" to requestedPermissions,
          "granted_permissions" to grantedPermissionsList,
          "pending_permissions" to pendingPermissionsList,
          "services" to servicesList,
          "receivers" to receiversList,
          "exported_components_count" to exportedComponentsCount,
          "has_accessibility" to hasAccessibility,
          "has_device_admin" to hasDeviceAdmin,
          "has_foreground_service" to hasForegroundService,
          "has_overlay" to hasOverlay,
          "has_boot_receiver" to hasBootReceiver,
          "read_sms_granted" to readSmsGranted,
          "read_contacts_granted" to readContactsGranted,
          "camera_granted" to cameraGranted,
          "record_audio_granted" to recordAudioGranted,
          "keylogger_detected" to keyloggerDetected,
          "has_battery_exemption" to hasBatteryExemption,
          "persistence_score" to persistenceScore,
          "accessibility_service_name" to accessibilityServiceName,
          "accessibility_service_enabled" to accessibilityServiceEnabled,
          "accessibility_capabilities" to accessibilityCapabilities,
          "overlay_granted" to overlayGranted,
          "device_admin_active" to deviceAdminActive,
          "is_device_owner" to isDeviceOwner,
          "is_profile_owner" to isProfileOwner
        )
        list.add(map)
      }
      list
    }
  }

  companion object {
    private val sha256Cache = java.util.concurrent.ConcurrentHashMap<String, Pair<Long, String>>()
  }

  private fun getApkSha256(apkPath: String): String {
    try {
      val file = java.io.File(apkPath)
      if (!file.exists()) return "Unknown"
      val digest = MessageDigest.getInstance("SHA-256")
      val fis = java.io.FileInputStream(file)
      val buffer = ByteArray(8192)
      var bytesRead: Int
      while (fis.read(buffer).also { bytesRead = it } != -1) {
        digest.update(buffer, 0, bytesRead)
      }
      fis.close()
      val hashBytes = digest.digest()
      val hexString = java.lang.StringBuilder()
      for (b in hashBytes) {
        val hex = Integer.toHexString(0xff and b.toInt())
        if (hex.length == 1) hexString.append('0')
        hexString.append(hex)
      }
      return hexString.toString().uppercase()
    } catch (e: Exception) {
      return "Unknown"
    }
  }

  private fun getCertificateFingerprint(pm: PackageManager, packageName: String): String {
    try {
      val signatures: Array<Signature>? = if (Build.VERSION.SDK_INT >= 28) {
        val packageInfo = pm.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        packageInfo.signingInfo?.apkContentsSigners
      } else {
        @Suppress("DEPRECATION")
        val packageInfo = pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES)
        packageInfo.signatures
      }

      if (signatures != null && signatures.isNotEmpty()) {
        val cert = signatures[0].toByteArray()
        val md = MessageDigest.getInstance("SHA-256")
        val publicKey = md.digest(cert)
        val hexString = java.lang.StringBuilder()
        for (i in publicKey.indices) {
          val appendString = Integer.toHexString(0xFF and publicKey[i].toInt())
          if (appendString.length == 1) hexString.append("0")
          hexString.append(appendString)
        }
        return hexString.toString().uppercase().chunked(2).joinToString(":")
      }
    } catch (e: Exception) {
      // ignore
    }
    return "Unknown"
  }
}
