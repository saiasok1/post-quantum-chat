import { useState } from "react";
import { Shield, Copy, CheckCircle, ArrowRight, Key } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";

interface KeyExchangePanelProps {
  localPublicKey?: string;
  peerPublicKey?: string;
  onGenerateKeys: () => void;
  onSharePublicKey: (publicKey: string) => void;
  keyFingerprint?: string;
  status: "idle" | "generating" | "exchanging" | "verified";
}

export function KeyExchangePanel({
  localPublicKey,
  peerPublicKey,
  onGenerateKeys,
  onSharePublicKey,
  keyFingerprint,
  status
}: KeyExchangePanelProps) {
  const { toast } = useToast();
  const [copied, setCopied] = useState(false);

  const copyToClipboard = async (text: string) => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    toast({
      title: "Copied to clipboard",
      description: "Public key copied successfully",
    });
    setTimeout(() => setCopied(false), 2000);
  };

  const steps = [
    { label: "Generate", active: status === "idle" || status === "generating" },
    { label: "Exchange", active: status === "exchanging" },
    { label: "Verify", active: status === "verified" },
  ];

  return (
    <Card className="border-border" data-testid="card-key-exchange">
      <CardHeader className="pb-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="h-5 w-5 text-primary" />
            <CardTitle className="text-lg">Post-Quantum Key Exchange</CardTitle>
          </div>
          <Badge 
            variant="outline" 
            className={cn(
              "gap-1",
              status === "verified" && "bg-success/10 text-success border-success/20",
              status === "generating" && "bg-warning/10 text-warning border-warning/20"
            )}
            data-testid="badge-key-status"
          >
            {status === "verified" && <CheckCircle className="h-3 w-3" />}
            {status === "verified" ? "Verified" : status === "generating" ? "Generating..." : "Pending"}
          </Badge>
        </div>
        <CardDescription>
          ML-KEM-768 key encapsulation for quantum-safe encryption
        </CardDescription>
      </CardHeader>

      <CardContent className="space-y-4">
        <div className="flex items-center justify-between gap-2 p-2 bg-muted/50 rounded-lg">
          {steps.map((step, idx) => (
            <div key={step.label} className="flex items-center gap-2">
              <div
                className={cn(
                  "flex items-center justify-center w-8 h-8 rounded-full text-xs font-medium transition-colors",
                  step.active 
                    ? "bg-primary text-primary-foreground" 
                    : "bg-muted text-muted-foreground"
                )}
              >
                {idx + 1}
              </div>
              <span className={cn(
                "text-sm font-medium",
                step.active ? "text-foreground" : "text-muted-foreground"
              )}>
                {step.label}
              </span>
              {idx < steps.length - 1 && (
                <ArrowRight className="h-4 w-4 text-muted-foreground ml-2" />
              )}
            </div>
          ))}
        </div>

        {!localPublicKey ? (
          <Button 
            onClick={onGenerateKeys} 
            className="w-full gap-2"
            data-testid="button-generate-keys"
          >
            <Key className="h-4 w-4" />
            Generate PQC Keys
          </Button>
        ) : (
          <div className="space-y-3">
            <div>
              <label className="text-sm font-medium mb-2 block">Your Public Key</label>
              <div className="flex gap-2">
                <div className="flex-1 p-3 bg-muted rounded-lg font-mono text-xs break-all max-h-20 overflow-auto">
                  {localPublicKey.slice(0, 64)}...
                </div>
                <Button
                  size="icon"
                  variant="outline"
                  onClick={() => copyToClipboard(localPublicKey)}
                  data-testid="button-copy-key"
                >
                  {copied ? <CheckCircle className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
                </Button>
              </div>
            </div>

            {keyFingerprint && (
              <div>
                <label className="text-sm font-medium mb-2 block">Key Fingerprint</label>
                <div className="p-3 bg-muted rounded-lg">
                  <div className="font-mono text-xs text-center tracking-wider">
                    {keyFingerprint}
                  </div>
                </div>
              </div>
            )}

            {peerPublicKey && (
              <div className="pt-2 border-t">
                <div className="flex items-center gap-2 mb-2">
                  <CheckCircle className="h-4 w-4 text-success" />
                  <span className="text-sm font-medium text-success">Peer Key Received</span>
                </div>
                <div className="p-3 bg-success/5 border border-success/20 rounded-lg font-mono text-xs break-all max-h-20 overflow-auto">
                  {peerPublicKey.slice(0, 64)}...
                </div>
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
