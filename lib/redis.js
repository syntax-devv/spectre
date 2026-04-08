const redis = require('redis');

class RedisClient {
  constructor() {
    this.client = null;
    this.isConnected = false;
  }

  async connect() {
    try {
      const redisUrl = process.env.REDIS_URL;
      
      let clientConfig = {
        socket: {
          connectTimeout: 5000,
          lazyConnect: true,
        },
      };

      if (process.env.REDIS_URL) {
        clientConfig.url = redisUrl;
      }
      this.client = redis.createClient(clientConfig);

      this.client.on('error', (err) => {
        console.error('Redis Client Error:', err);
        this.isConnected = false;
      });

      this.client.on('connect', () => {
        console.log('Redis Client Connected');
        this.isConnected = true;
      });

      this.client.on('ready', () => {
        console.log('Redis Client Ready');
      });

      this.client.on('end', () => {
        console.log('Redis Client Disconnected');
        this.isConnected = false;
      });

      await this.client.connect();
      return this.client;
    } catch (error) {
      console.error('Failed to connect to Redis:', error);
      throw error;
    }
  }

  async disconnect() {
    if (this.client) {
      await this.client.disconnect();
    }
  }

  getClient() {
    return this.client;
  }

  isReady() {
    return this.isConnected && this.client;
  }
}

const redisClient = new RedisClient();

// Handle graceful shutdown
process.on('beforeExit', async () => {
  await redisClient.disconnect();
});

process.on('SIGINT', async () => {
  await redisClient.disconnect();
  process.exit(0);
});

module.exports = redisClient;
