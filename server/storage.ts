import type { Message, InsertMessage } from "@shared/schema";
import { randomUUID } from "crypto";

export interface IStorage {
  saveMessage(message: InsertMessage): Promise<Message>;
  getMessages(): Promise<Message[]>;
  deleteAllMessages(): Promise<void>;
}

export class MemStorage implements IStorage {
  private messages: Map<string, Message>;

  constructor() {
    this.messages = new Map();
  }

  async saveMessage(insertMessage: InsertMessage): Promise<Message> {
    const id = randomUUID();
    const timestamp = Date.now();
    const message: Message = { ...insertMessage, id, timestamp };
    this.messages.set(id, message);
    return message;
  }

  async getMessages(): Promise<Message[]> {
    return Array.from(this.messages.values()).sort((a, b) => a.timestamp - b.timestamp);
  }

  async deleteAllMessages(): Promise<void> {
    this.messages.clear();
  }
}

export const storage = new MemStorage();
