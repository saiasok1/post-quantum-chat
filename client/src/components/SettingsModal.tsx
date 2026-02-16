import { Settings, Sun, Moon, Shield, Zap, RotateCcw } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useTheme } from "./ThemeProvider";
import { useSettings } from "@/contexts/SettingsContext";
import { Badge } from "@/components/ui/badge";

export function SettingsModal() {
  const { theme, setTheme } = useTheme();
  const { settings, updateSetting, resetSettings } = useSettings();

  return (
    <Dialog>
      <DialogTrigger asChild>
        <Button variant="ghost" size="icon" data-testid="button-settings">
          <Settings className="h-5 w-5" />
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-2xl" data-testid="modal-settings">
        <DialogHeader>
          <div className="flex items-center justify-between">
            <div>
              <DialogTitle className="text-2xl">Settings</DialogTitle>
              <DialogDescription>
                Configure your PQC chat security and appearance preferences
              </DialogDescription>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={resetSettings}
              className="gap-2"
              data-testid="button-reset-settings"
            >
              <RotateCcw className="h-4 w-4" />
              Reset
            </Button>
          </div>
        </DialogHeader>

        <Tabs defaultValue="security" className="mt-4">
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="security" data-testid="tab-security">Security</TabsTrigger>
            <TabsTrigger value="appearance" data-testid="tab-appearance">Appearance</TabsTrigger>
            <TabsTrigger value="advanced" data-testid="tab-advanced">Advanced</TabsTrigger>
          </TabsList>

          <TabsContent value="security" className="space-y-4 mt-4">
            <div className="space-y-4">
              <div className="flex items-start gap-3 p-4 bg-muted/50 rounded-lg">
                <Shield className="h-5 w-5 text-primary mt-0.5" />
                <div className="flex-1">
                  <h3 className="font-medium mb-1">Post-Quantum Algorithms</h3>
                  <p className="text-sm text-muted-foreground mb-3">
                    Configure the cryptographic algorithms used for encryption
                  </p>

                  <div className="space-y-3">
                    <div>
                      <Label className="text-xs font-medium">Key Encapsulation Mechanism</Label>
                      <Select
                        value={settings.kemAlgorithm}
                        onValueChange={(value: "ml-kem-512" | "ml-kem-768" | "ml-kem-1024") =>
                          updateSetting("kemAlgorithm", value)
                        }
                      >
                        <SelectTrigger className="mt-1">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="ml-kem-512">ML-KEM-512 (128-bit security)</SelectItem>
                          <SelectItem value="ml-kem-768">ML-KEM-768 (192-bit security)</SelectItem>
                          <SelectItem value="ml-kem-1024">ML-KEM-1024 (256-bit security)</SelectItem>
                          <SelectItem value="kyber-512">Kyber-512 (Legacy)</SelectItem>
                          <SelectItem value="kyber-768">Kyber-768 (Legacy)</SelectItem>
                          <SelectItem value="kyber-1024">Kyber-1024 (Legacy)</SelectItem>
                          <SelectItem value="rsa-2048">RSA-2048 (Classic 112-bit)</SelectItem>
                          <SelectItem value="rsa-4096">RSA-4096 (Classic 128-bit)</SelectItem>
                          <SelectItem value="ecdh-p256">ECDH P-256 (Classic 128-bit)</SelectItem>
                          <SelectItem value="ecdh-p384">ECDH P-384 (Classic 192-bit)</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>

                    <div>
                      <Label className="text-xs font-medium">Digital Signature Algorithm</Label>
                      <Select
                        value={settings.signatureAlgorithm}
                        onValueChange={(value: any) =>
                          updateSetting("signatureAlgorithm", value)
                        }
                      >
                        <SelectTrigger className="mt-1">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="ml-dsa-44">ML-DSA-44 (128-bit security)</SelectItem>
                          <SelectItem value="ml-dsa-65">ML-DSA-65 (192-bit security)</SelectItem>
                          <SelectItem value="ml-dsa-87">ML-DSA-87 (256-bit security)</SelectItem>
                          <SelectItem value="rsa-pss-2048">RSA-PSS-2048 (Classic)</SelectItem>
                          <SelectItem value="rsa-pss-4096">RSA-PSS-4096 (Classic)</SelectItem>
                          <SelectItem value="ecdsa-p256">ECDSA P-256 (Classic)</SelectItem>
                          <SelectItem value="ecdsa-p384">ECDSA P-384 (Classic)</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                </div>
              </div>

              <div className="flex items-center justify-between p-4 border rounded-lg">
                <div className="space-y-0.5">
                  <Label>Auto Key Rotation</Label>
                  <p className="text-sm text-muted-foreground">
                    Automatically rotate encryption keys every 24 hours
                  </p>
                </div>
                <Switch
                  checked={settings.autoKeyRotation}
                  onCheckedChange={(checked) => updateSetting("autoKeyRotation", checked)}
                  data-testid="switch-auto-rotation"
                />
              </div>

              <div className="flex items-center justify-between p-4 border rounded-lg">
                <div className="space-y-0.5">
                  <Label>Perfect Forward Secrecy</Label>
                  <p className="text-sm text-muted-foreground">
                    Generate new session keys for each conversation
                  </p>
                </div>
                <Switch
                  checked={settings.perfectForwardSecrecy}
                  onCheckedChange={(checked) => updateSetting("perfectForwardSecrecy", checked)}
                  data-testid="switch-forward-secrecy"
                />
              </div>
            </div>
          </TabsContent>

          <TabsContent value="appearance" className="space-y-4 mt-4">
            <div className="space-y-4">
              <div>
                <Label className="mb-3 block">Theme</Label>
                <div className="grid grid-cols-3 gap-2">
                  <Button
                    variant={theme === "light" ? "default" : "outline"}
                    onClick={() => setTheme("light")}
                    className="gap-2"
                    data-testid="button-theme-light"
                  >
                    <Sun className="h-4 w-4" />
                    Light
                  </Button>
                  <Button
                    variant={theme === "dark" ? "default" : "outline"}
                    onClick={() => setTheme("dark")}
                    className="gap-2"
                    data-testid="button-theme-dark"
                  >
                    <Moon className="h-4 w-4" />
                    Dark
                  </Button>
                  <Button
                    variant={theme === "system" ? "default" : "outline"}
                    onClick={() => setTheme("system")}
                    className="gap-2"
                    data-testid="button-theme-system"
                  >
                    <Zap className="h-4 w-4" />
                    System
                  </Button>
                </div>
              </div>

              <div className="flex items-center justify-between p-4 border rounded-lg">
                <div className="space-y-0.5">
                  <Label>Show Encryption Indicators</Label>
                  <p className="text-sm text-muted-foreground">
                    Display PQC badges on encrypted messages
                  </p>
                </div>
                <Switch
                  checked={settings.showEncryptionIndicators}
                  onCheckedChange={(checked) => updateSetting("showEncryptionIndicators", checked)}
                  data-testid="switch-encryption-indicators"
                />
              </div>

              <div className="flex items-center justify-between p-4 border rounded-lg">
                <div className="space-y-0.5">
                  <Label>Compact Message View</Label>
                  <p className="text-sm text-muted-foreground">
                    Reduce spacing between messages
                  </p>
                </div>
                <Switch
                  checked={settings.compactMessageView}
                  onCheckedChange={(checked) => updateSetting("compactMessageView", checked)}
                  data-testid="switch-compact-view"
                />
              </div>
            </div>
          </TabsContent>

          <TabsContent value="advanced" className="space-y-4 mt-4">
            <div className="space-y-4">
              <div className="p-4 bg-warning/10 border border-warning/20 rounded-lg">
                <h3 className="font-medium mb-2 text-warning">Advanced Settings</h3>
                <p className="text-sm text-muted-foreground">
                  These settings affect core cryptographic operations. Only modify if you understand the implications.
                </p>
              </div>

              <div className="flex items-center justify-between p-4 border rounded-lg">
                <div className="space-y-0.5">
                  <Label>WebSocket Auto-Reconnect</Label>
                  <p className="text-sm text-muted-foreground">
                    Automatically reconnect on connection loss
                  </p>
                </div>
                <Switch
                  checked={settings.autoReconnect}
                  onCheckedChange={(checked) => updateSetting("autoReconnect", checked)}
                  data-testid="switch-auto-reconnect"
                />
              </div>

              <div className="flex items-center justify-between p-4 border rounded-lg">
                <div className="space-y-0.5">
                  <Label>Enable Message Signatures</Label>
                  <p className="text-sm text-muted-foreground">
                    Sign all messages with {settings.signatureAlgorithm.toUpperCase()} (increases latency)
                  </p>
                </div>
                <Switch
                  checked={settings.enableMessageSignatures}
                  onCheckedChange={(checked) => updateSetting("enableMessageSignatures", checked)}
                  data-testid="switch-message-signatures"
                />
              </div>

              <div className="flex items-center justify-between p-4 border rounded-lg">
                <div className="space-y-0.5">
                  <Label>Debug Mode</Label>
                  <p className="text-sm text-muted-foreground">
                    Show technical details and connection logs
                  </p>
                </div>
                <Switch
                  checked={settings.debugMode}
                  onCheckedChange={(checked) => updateSetting("debugMode", checked)}
                  data-testid="switch-debug-mode"
                />
              </div>
            </div>
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  );
}
