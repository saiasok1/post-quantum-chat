import { Lock } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import type { Message } from "@shared/schema";
import { cn } from "@/lib/utils";

interface ChatMessageProps {
  message: Message;
  isOwn: boolean;
}

export function ChatMessage({ message, isOwn }: ChatMessageProps) {
  const timestamp = new Date(message.timestamp).toLocaleTimeString([], { 
    hour: '2-digit', 
    minute: '2-digit' 
  });

  return (
    <div
      className={cn(
        "flex w-full mb-3",
        isOwn ? "justify-end" : "justify-start"
      )}
      data-testid={`message-${message.id}`}
    >
      <div className={cn("flex flex-col", isOwn ? "items-end" : "items-start")}>
        <div
          className={cn(
            "px-4 py-3 relative",
            isOwn
              ? "bg-primary text-primary-foreground rounded-2xl rounded-br-sm max-w-md"
              : "bg-card text-card-foreground rounded-2xl rounded-bl-sm max-w-md border border-card-border"
          )}
        >
          {message.type === "image" && message.imageUrl ? (
            <div className="relative">
              <img
                src={message.imageUrl}
                alt="Shared image"
                className="rounded-xl max-h-96 object-cover"
                data-testid={`image-${message.id}`}
              />
              {message.encrypted && (
                <div className="absolute top-2 right-2 bg-black/50 backdrop-blur-sm rounded-full p-1.5">
                  <Lock className="h-3 w-3 text-white" />
                </div>
              )}
              {message.content && (
                <p className="mt-2 text-sm">{message.content}</p>
              )}
            </div>
          ) : (
            <p className="text-base leading-relaxed break-words whitespace-pre-wrap">
              {message.content}
            </p>
          )}
        </div>
        
        <div className="flex items-center gap-2 mt-1 px-1">
          <span className="text-xs text-muted-foreground" data-testid={`timestamp-${message.id}`}>
            {timestamp}
          </span>
          {message.encrypted && (
            <Badge 
              variant="outline" 
              className="text-xs px-1.5 py-0 h-4 bg-success/10 text-success border-success/20"
              data-testid={`badge-encrypted-${message.id}`}
            >
              <Lock className="h-2.5 w-2.5 mr-1" />
              PQC
            </Badge>
          )}
        </div>
      </div>
    </div>
  );
}
