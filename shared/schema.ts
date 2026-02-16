import { z } from "zod";

// Message types
export const messageSchema = z.object({
  id: z.string(),
  senderId: z.string(),
  receiverId: z.string(),
  content: z.string(),
  type: z.enum(["text", "image"]),
  encrypted: z.boolean(),
  timestamp: z.number(),
  imageUrl: z.string().optional(),
});

export const insertMessageSchema = messageSchema.omit({ id: true, timestamp: true });

export type Message = z.infer<typeof messageSchema>;
export type InsertMessage = z.infer<typeof insertMessageSchema>;

// PQC Key types
export const pqcKeyPairSchema = z.object({
  publicKey: z.string(),
  privateKey: z.string(),
  kemAlgorithm: z.enum([
    "ml-kem-512", "ml-kem-768", "ml-kem-1024", 
    "kyber-512", "kyber-768", "kyber-1024",
    "rsa-2048", "rsa-4096",
    "ecdh-p256", "ecdh-p384"
  ]),
  signatureAlgorithm: z.enum([
    "ml-dsa-44", "ml-dsa-65", "ml-dsa-87",
    "rsa-pss-2048", "rsa-pss-4096", 
    "ecdsa-p256", "ecdsa-p384"
  ]),
  timestamp: z.number(),
});

export type PQCKeyPair = z.infer<typeof pqcKeyPairSchema>;

// User/Peer types
export const peerSchema = z.object({
  id: z.string(),
  publicKey: z.string().optional(),
  status: z.enum(["online", "offline", "key-exchange"]),
  lastSeen: z.number(),
});

export type Peer = z.infer<typeof peerSchema>;

// WebSocket message types
export const wsMessageSchema = z.discriminatedUnion("type", [
  z.object({
    type: z.literal("chat"),
    payload: messageSchema,
  }),
  z.object({
    type: z.literal("key-exchange"),
    payload: z.object({
      publicKey: z.string(),
      kemAlgorithm: z.string(),
      signatureAlgorithm: z.string(),
      ciphertext: z.string().optional(),
    }),
  }),
  z.object({
    type: z.literal("peer-status"),
    payload: z.object({
      peerId: z.string(),
      status: z.enum(["online", "offline"]),
    }),
  }),
  z.object({
    type: z.literal("connection"),
    payload: z.object({
      peerId: z.string(),
    }),
  }),
]);

export type WSMessage = z.infer<typeof wsMessageSchema>;
