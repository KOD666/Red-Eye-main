import { requireNativeModule } from 'expo';

let InstalledAppsModule = null;
try {
  InstalledAppsModule = requireNativeModule('InstalledApps');
} catch (e) {
  // Graceful fallback for non-native / Expo Go client runtimes
  InstalledAppsModule = {
    getInstalledApps: () => {
      throw new Error("Native InstalledApps module not available in this runtime (Expo Go/Dev Client sandbox)");
    }
  };
}

export default InstalledAppsModule;
