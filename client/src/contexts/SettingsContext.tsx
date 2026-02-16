
import { createContext, useContext, useEffect, useState, ReactNode } from "react";
import { KemAlgorithm, SignatureAlgorithm } from "@/lib/crypto";

export interface AppSettings {
  // Security settings
  autoKeyRotation: boolean;
  perfectForwardSecrecy: boolean;

  // Appearance settings
  showEncryptionIndicators: boolean;
  compactMessageView: boolean;

  // Advanced settings
  autoReconnect: boolean;
  enableMessageSignatures: boolean;
  debugMode: boolean;

  // Crypto settings
  kemAlgorithm: KemAlgorithm;
  signatureAlgorithm: SignatureAlgorithm;
}

const defaultSettings: AppSettings = {
  // Security defaults
  autoKeyRotation: true,
  perfectForwardSecrecy: true,

  // Appearance defaults
  showEncryptionIndicators: true,
  compactMessageView: false,

  // Advanced defaults
  autoReconnect: true,
  enableMessageSignatures: false,
  debugMode: false,

  // Crypto defaults
  kemAlgorithm: "ml-kem-768",
  signatureAlgorithm: "ml-dsa-65"
};

interface SettingsContextType {
  settings: AppSettings;
  updateSetting: <K extends keyof AppSettings>(key: K, value: AppSettings[K]) => void;
  resetSettings: () => void;
}

const SettingsContext = createContext<SettingsContextType | undefined>(undefined);

export function SettingsProvider({ children }: { children: ReactNode }) {
  const [settings, setSettings] = useState<AppSettings>(() => {
    try {
      const stored = localStorage.getItem("pqc-chat-settings");
      if (stored) {
        const parsed = JSON.parse(stored);
        // Merge with defaults to handle new settings
        return { ...defaultSettings, ...parsed };
      }
    } catch (error) {
      console.error("Failed to load settings from localStorage:", error);
    }
    return defaultSettings;
  });

  // Save to localStorage whenever settings change
  useEffect(() => {
    try {
      localStorage.setItem("pqc-chat-settings", JSON.stringify(settings));
      console.log("⚙️ Settings saved:", settings);
    } catch (error) {
      console.error("Failed to save settings to localStorage:", error);
    }
  }, [settings]);

  const updateSetting = <K extends keyof AppSettings>(key: K, value: AppSettings[K]) => {
    setSettings(prev => ({
      ...prev,
      [key]: value
    }));
  };

  const resetSettings = () => {
    setSettings(defaultSettings);
  };

  return (
    <SettingsContext.Provider value={{ settings, updateSetting, resetSettings }}>
      {children}
    </SettingsContext.Provider>
  );
}

export function useSettings() {
  const context = useContext(SettingsContext);
  if (!context) {
    throw new Error("useSettings must be used within SettingsProvider");
  }
  return context;
}