import type { Express } from "express";
import { createServer, type Server } from "http";
import { WebSocketServer, WebSocket } from "ws";
import multer from "multer";
import sharp from "sharp";
import { randomUUID } from "crypto";
import type { WSMessage } from "@shared/schema";

const upload = multer({ storage: multer.memoryStorage() });

export async function registerRoutes(app: Express): Promise<Server> {
  const httpServer = createServer(app);
  const wss = new WebSocketServer({ server: httpServer, path: '/ws' });

  const clients = new Map<string, { ws: WebSocket; peerId: string }>();

  wss.on('connection', (ws: WebSocket) => {
    const peerId = randomUUID();
    clients.set(peerId, { ws, peerId });

    const connectionMsg: WSMessage = {
      type: 'connection',
      payload: { peerId },
    };
    ws.send(JSON.stringify(connectionMsg));

    console.log(`Client connected: ${peerId}`);

    ws.on('message', (data: Buffer) => {
      try {
        const message: WSMessage = JSON.parse(data.toString());

        clients.forEach((client) => {
          if (client.peerId !== peerId && client.ws.readyState === WebSocket.OPEN) {
            client.ws.send(JSON.stringify(message));
          }
        });
      } catch (error) {
        console.error('Error processing message:', error);
      }
    });

    ws.on('close', () => {
      clients.delete(peerId);
      console.log(`Client disconnected: ${peerId}`);

      const statusMsg: WSMessage = {
        type: 'peer-status',
        payload: {
          peerId,
          status: 'offline',
        },
      };

      clients.forEach((client) => {
        if (client.ws.readyState === WebSocket.OPEN) {
          client.ws.send(JSON.stringify(statusMsg));
        }
      });
    });

    ws.on('error', (error) => {
      console.error(`WebSocket error for ${peerId}:`, error);
    });
  });

  app.post('/api/upload-image', upload.single('image'), async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ error: 'No image file provided' });
      }

      const processedImage = await sharp(req.file.buffer)
        .resize(1200, 1200, { fit: 'inside', withoutEnlargement: true })
        .jpeg({ quality: 85 })
        .toBuffer();

      const base64Image = `data:image/jpeg;base64,${processedImage.toString('base64')}`;

      res.json({ imageUrl: base64Image });
    } catch (error) {
      console.error('Image upload error:', error);
      res.status(500).json({ error: 'Failed to process image' });
    }
  });

  return httpServer;
}
