import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

interface ConnectionStatusProps {
  status: "online" | "offline" | "key-exchange";
  className?: string;
}

export function ConnectionStatus({ status, className }: ConnectionStatusProps) {
  const statusConfig = {
    online: {
      label: "Online",
      color: "bg-status-online",
      badgeClass: "bg-success/10 text-success border-success/20"
    },
    offline: {
      label: "Offline",
      color: "bg-status-offline",
      badgeClass: "bg-muted text-muted-foreground border-muted-foreground/20"
    },
    "key-exchange": {
      label: "Key Exchange",
      color: "bg-status-away",
      badgeClass: "bg-warning/10 text-warning border-warning/20"
    }
  };

  const config = statusConfig[status];

  return (
    <Badge 
      variant="outline" 
      className={cn("gap-1.5 px-2.5 py-1", config.badgeClass, className)}
      data-testid={`status-${status}`}
    >
      <span className={cn("h-2 w-2 rounded-full animate-pulse", config.color)} />
      {config.label}
    </Badge>
  );
}
