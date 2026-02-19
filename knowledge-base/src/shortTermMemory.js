// Short-term Memory using Redis
// Handles conversation context, recent learnings, temporary data

import Redis from 'ioredis';

const DEFAULT_TTL = 3600; // 1 hour for conversations
const CONTEXT_TTL = 300; // 5 minutes for active context

class ShortTermMemory {
    constructor(options = {}) {
        this.redis = null;
        this.host = options.host || 'localhost';
        this.port = options.port || 6379;
        this.connected = false;
    }

    async connect() {
        try {
            this.redis = new Redis({
                host: this.host,
                port: this.port,
                retryDelayOnFailover: 100,
                maxRetriesPerRequest: 3
            });

            this.redis.on('connect', () => {
                this.connected = true;
                console.log('✅ Redis connected (short-term memory)');
            });

            this.redis.on('error', (err) => {
                console.log('⚠️  Redis error:', err.message);
                this.connected = false;
            });

            // Test connection
            await this.redis.ping();
            return true;
        } catch (error) {
            console.log('❌ Redis connection failed:', error.message);
            return false;
        }
    }

    async disconnect() {
        if (this.redis) {
            await this.redis.quit();
        }
    }

    // Store conversation context
    async storeContext(sessionId, messages, ttl = CONTEXT_TTL) {
        if (!this.connected) return { error: 'Redis not connected' };

        const key = `context:${sessionId}`;
        await this.redis.setex(key, ttl, JSON.stringify(messages));
        
        return { success: true, ttl };
    }

    // Get conversation context
    async getContext(sessionId) {
        if (!this.connected) return { error: 'Redis not connected' };

        const key = `context:${sessionId}`;
        const data = await this.redis.get(key);
        
        return data ? JSON.parse(data) : null;
    }

    // Store a recent learning (short-term fact)
    async storeLearning(key, value, ttl = DEFAULT_TTL) {
        if (!this.connected) return { error: 'Redis not connected' };

        const fullKey = `learning:${key}`;
        await this.redis.setex(fullKey, ttl, JSON.stringify(value));
        
        return { success: true, key, ttl };
    }

    // Get recent learning
    async getLearning(key) {
        if (!this.connected) return { error: 'Redis not connected' };

        const fullKey = `learning:${key}`;
        const data = await this.redis.get(fullKey);
        
        return data ? JSON.parse(data) : null;
    }

    // Get all recent learnings (last hour)
    async getRecentLearnings() {
        if (!this.connected) return [];

        const keys = await this.redis.keys('learning:*');
        const learnings = [];

        for (const key of keys) {
            const data = await this.redis.get(key);
            if (data) {
                const shortKey = key.replace('learning:', '');
                learnings.push({ key: shortKey, ...JSON.parse(data) });
            }
        }

        return learnings;
    }

    // Store conversation message
    async addMessage(sessionId, message) {
        if (!this.connected) return { error: 'Redis not connected' };

        const key = `messages:${sessionId}`;
        const messageData = {
            ...message,
            timestamp: new Date().toISOString()
        };

        // Add to list and keep last 50 messages
        await this.redis.lpush(key, JSON.stringify(messageData));
        await this.redis.ltrim(key, 0, 49);
        // Expire after 24 hours of inactivity
        await this.redis.expire(key, 86400);

        return { success: true };
    }

    // Get conversation history
    async getMessages(sessionId, limit = 20) {
        if (!this.connected) return [];

        const key = `messages:${sessionId}`;
        const messages = await this.redis.lrange(key, 0, limit - 1);
        
        return messages.map(m => JSON.parse(m));
    }

    // Store user preference (temporary)
    async setPreference(userId, key, value) {
        if (!this.connected) return { error: 'Redis not connected' };

        const prefKey = `pref:${userId}:${key}`;
        await this.redis.set(prefKey, JSON.stringify(value));
        
        return { success: true };
    }

    // Get user preference
    async getPreference(userId, key) {
        if (!this.connected) return null;

        const prefKey = `pref:${userId}:${key}`;
        const data = await this.redis.get(prefKey);
        
        return data ? JSON.parse(data) : null;
    }

    // Track active session
    async setActiveSession(userId, sessionId) {
        if (!this.connected) return;

        const key = `active:${userId}`;
        await this.redis.set(key, sessionId);
        await this.redis.expire(key, 86400); // 24 hours
    }

    // Get active session
    async getActiveSession(userId) {
        if (!this.connected) return null;

        const key = `active:${userId}`;
        return await this.redis.get(key);
    }

    // Clear short-term memory (for testing)
    async clear() {
        if (!this.connected) return;

        const keys = await this.redis.keys('*');
        if (keys.length > 0) {
            await this.redis.del(...keys);
        }
        
        return { cleared: true, keysDeleted: keys.length };
    }

    // Get memory stats
    async getStats() {
        if (!this.connected) {
            return { connected: false };
        }

        const info = await this.redis.info('memory');
        const keys = await this.redis.dbsize();
        
        return {
            connected: true,
            keys,
            memory: info.split('\n').find(l => l.startsWith('used_memory_human'))?.split(':')[1]?.trim() || 'N/A'
        };
    }

    // Promote to long-term (mark for migration)
    async markForLongTerm(key) {
        if (!this.connected) return;

        const fullKey = `learning:${key}`;
        const data = await this.redis.get(fullKey);
        
        if (data) {
            // Store in a special set for migration
            await this.redis.sadd('longterm:queue', JSON.stringify({ key, data }));
        }
        
        return { queued: true, key };
    }

    // Get items queued for long-term storage
    async getLongTermQueue() {
        if (!this.connected) return [];

        const items = await this.redis.smembers('longterm:queue');
        return items.map(i => JSON.parse(i));
    }
}

export default ShortTermMemory;
