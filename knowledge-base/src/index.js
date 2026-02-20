// Knowledge Base - Combined Short and Long-term Memory
// Unifies Redis (short-term) and PostgreSQL (long-term)

import ShortTermMemory from './shortTermMemory.js';
import LongTermMemory from './longTermMemory.js';

class KnowledgeBase {
    constructor(options = {}) {
        this.shortTerm = new ShortTermMemory({
            host: options.redisHost || 'localhost',
            port: options.redisPort || 6379
        });

        this.longTerm = new LongTermMemory({
            host: options.postgresHost || 'localhost',
            port: options.postgresPort || 5432,
            database: options.database || 'knowledge_base',
            user: options.user || process.env.POSTGRES_USER || 'opencode',
            password: options.password || ''
        });

        this.connected = false;
    }

    async initialize() {
        console.log('🧠 Initializing Knowledge Base...\n');

        // Connect to both
        const redisOk = await this.shortTerm.connect();
        const postgresOk = await this.longTerm.connect();

        this.connected = redisOk && postgresOk;

        if (this.connected) {
            console.log('\n✅ Knowledge Base ready!');
        } else {
            console.log('\n⚠️  Knowledge Base partially available:');
            console.log(`   Redis (short-term): ${redisOk ? '✅' : '❌'}`);
            console.log(`   PostgreSQL (long-term): ${postgresOk ? '✅' : '❌'}`);
        }

        return this.connected;
    }

    async disconnect() {
        await this.shortTerm.disconnect();
        await this.longTerm.disconnect();
    }

    // Learn something new
    async learn(key, value, options = {}) {
        const { permanent = false, category, tags, source, ttl } = options;

        if (permanent) {
            // Store in long-term memory (PostgreSQL)
            return await this.longTerm.store(key, value, { category, tags, source });
        } else {
            // Store in short-term memory (Redis)
            return await this.shortTerm.storeLearning(key, value, ttl);
        }
    }

    // Recall something
    async recall(key) {
        // Try short-term first
        let result = await this.shortTerm.getLearning(key);
        
        if (result) {
            return { ...result, source: 'short-term' };
        }

        // Try long-term
        result = await this.longTerm.retrieve(key);
        
        if (result) {
            return { ...result, source: 'long-term' };
        }

        return null;
    }

    // Search everything
    async search(query, options = {}) {
        const { category, limit } = options;

        const results = {
            shortTerm: await this.shortTerm.getRecentLearnings(),
            longTerm: await this.longTerm.search(query, { category, limit }),
            fullText: await this.longTerm.fullTextSearch(query)
        };

        return results;
    }

    // Store conversation context
    async storeContext(sessionId, messages) {
        return await this.shortTerm.storeContext(sessionId, messages);
    }

    // Get conversation context
    async getContext(sessionId) {
        return await this.shortTerm.getContext(sessionId);
    }

    // Add message to conversation
    async addMessage(sessionId, message) {
        return await this.shortTerm.addMessage(sessionId, message);
    }

    // Get conversation history
    async getHistory(sessionId, limit) {
        return await this.shortTerm.getMessages(sessionId, limit);
    }

    // Project management
    async createProject(name, description, options = {}) {
        return await this.longTerm.storeProject(name, description, options);
    }

    async getProject(name) {
        return await this.longTerm.getProject(name);
    }

    async listProjects(status) {
        return await this.longTerm.listProjects(status);
    }

    // Research storage
    async storeResearch(topic, findings, sources) {
        return await this.longTerm.storeResearch(topic, findings, sources);
    }

    async getResearch(topic) {
        return await this.longTerm.getResearch(topic);
    }

    // Fact storage
    async storeFact(fact, options = {}) {
        return await this.longTerm.storeFact(fact, options);
    }

    async getFacts(category, limit) {
        return await this.longTerm.getFacts(category, limit);
    }

    // User preferences
    async setPreference(key, value) {
        return await this.longTerm.setPreference(key, value);
    }

    async getPreference(key) {
        return await this.longTerm.getPreference(key);
    }

    // Promote short-term to long-term
    async promote(key) {
        const data = await this.shortTerm.getLearning(key);
        
        if (data) {
            await this.longTerm.store(key, data.value || JSON.stringify(data), {
                category: data.category,
                tags: data.tags,
                source: 'promoted_from_shortterm'
            });
            
            // Remove from short-term
            // (would need method to delete specific key)
            
            return { promoted: true, key };
        }
        
        return { promoted: false, reason: 'Not found in short-term' };
    }

    // Get all recent (short-term) learnings
    async getRecentLearnings() {
        return await this.shortTerm.getRecentLearnings();
    }

    // Get full stats
    async getStats() {
        const shortTermStats = await this.shortTerm.getStats();
        const longTermStats = await this.longTerm.getStats();

        return {
            shortTerm: shortTermStats,
            longTerm: longTermStats,
            ready: this.connected
        };
    }

    // Clear short-term (for testing)
    async clearShortTerm() {
        return await this.shortTerm.clear();
    }
}

export default KnowledgeBase;
