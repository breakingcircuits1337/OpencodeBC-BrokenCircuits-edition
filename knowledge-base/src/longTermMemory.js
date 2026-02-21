// Long-term Memory using PostgreSQL
// Handles projects, facts, research, permanent knowledge

import pg from 'pg';
import { v4 as uuidv4 } from 'uuid';

const { Pool } = pg;

class LongTermMemory {
    constructor(options = {}) {
        this.pool = null;
        this.host = options.host || process.env.POSTGRES_HOST || 'localhost';
        this.port = options.port || process.env.POSTGRES_PORT || 5432;
        this.database = options.database || process.env.DATABASE || 'knowledge_base';
        this.user = options.user || process.env.POSTGRES_USER || 'opencode';
        this.password = options.password || process.env.POSTGRES_PASSWORD || 'sarah123';
        this.connected = false;
    }

    async connect() {
        try {
            this.pool = new Pool({
                host: this.host,
                port: this.port,
                database: this.database,
                user: this.user,
                password: this.password,
                max: 20,
                idleTimeoutMillis: 30000,
                connectionTimeoutMillis: 2000
            });

            // Test connection
            const client = await this.pool.connect();
            console.log('✅ PostgreSQL connected (long-term memory)');
            client.release();

            // Initialize tables
            await this.initializeTables();
            
            this.connected = true;
            return true;
        } catch (error) {
            console.log('❌ PostgreSQL connection failed:', error.message);
            return false;
        }
    }

    async initializeTables() {
        // Knowledge entries table
        await this.pool.query(`
            CREATE TABLE IF NOT EXISTS knowledge (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                key VARCHAR(500) UNIQUE NOT NULL,
                value TEXT NOT NULL,
                category VARCHAR(100),
                tags TEXT[],
                source VARCHAR(200),
                confidence FLOAT DEFAULT 1.0,
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW(),
                last_accessed TIMESTAMP,
                access_count INTEGER DEFAULT 0
            )
        `);

        // Projects table
        await this.pool.query(`
            CREATE TABLE IF NOT EXISTS projects (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                name VARCHAR(200) UNIQUE NOT NULL,
                description TEXT,
                status VARCHAR(50) DEFAULT 'active',
                tags TEXT[],
                data JSONB,
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW()
            )
        `);

        // Research table
        await this.pool.query(`
            CREATE TABLE IF NOT EXISTS research (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                topic VARCHAR(500) NOT NULL,
                findings TEXT,
                sources TEXT[],
                quality FLOAT DEFAULT 0.5,
                verified BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT NOW()
            )
        `);

        // Facts table
        await this.pool.query(`
            CREATE TABLE IF NOT EXISTS facts (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                fact TEXT NOT NULL,
                category VARCHAR(100),
                confidence FLOAT DEFAULT 0.5,
                source VARCHAR(200),
                verified BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT NOW()
            )
        `);

        // User profile table
        await this.pool.query(`
            CREATE TABLE IF NOT EXISTS user_profile (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                key VARCHAR(200) UNIQUE NOT NULL,
                value TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT NOW()
            )
        `);

        // Create indexes
        await this.pool.query(`
            CREATE INDEX IF NOT EXISTS idx_knowledge_category ON knowledge(category);
            CREATE INDEX IF NOT EXISTS idx_knowledge_tags ON knowledge USING GIN(tags);
            CREATE INDEX IF NOT EXISTS idx_research_topic ON research(topic);
            CREATE INDEX IF NOT EXISTS idx_facts_category ON facts(category);
        `);

        console.log('✅ Database tables initialized');
    }

    async disconnect() {
        if (this.pool) {
            await this.pool.end();
        }
    }

    // Store knowledge
    async store(key, value, options = {}) {
        const { category, tags, source, confidence } = options;

        const result = await this.pool.query(`
            INSERT INTO knowledge (key, value, category, tags, source, confidence)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (key) DO UPDATE SET
                value = EXCLUDED.value,
                category = COALESCE(EXCLUDED.category, knowledge.category),
                tags = COALESCE(EXCLUDED.tags, knowledge.tags),
                confidence = EXCLUDED.confidence,
                updated_at = NOW()
            RETURNING id
        `, [key, value, category || null, tags || null, source || null, confidence || 1.0]);

        return { id: result.rows[0].id, key };
    }

    // Retrieve knowledge
    async retrieve(key) {
        const result = await this.pool.query(`
            UPDATE knowledge 
            SET access_count = access_count + 1, last_accessed = NOW()
            WHERE key = $1
            RETURNING *
        `, [key]);

        return result.rows[0] || null;
    }

    // Search knowledge
    async search(query, options = {}) {
        const { category, tags, limit = 10 } = options;

        let sql = `
            SELECT * FROM knowledge 
            WHERE (key ILIKE $1 OR value ILIKE $1)
        `;
        const params = [`%${query}%`];

        if (category) {
            params.push(category);
            sql += ` AND category = $${params.length}`;
        }

        if (tags && tags.length > 0) {
            params.push(tags);
            sql += ` AND tags && $${params.length}`;
        }

        params.push(limit);
        sql += ` ORDER BY access_count DESC, confidence DESC LIMIT $${params.length}`;

        const result = await this.pool.query(sql, params);
        return result.rows;
    }

    // Get all by category
    async getByCategory(category) {
        const result = await this.pool.query(`
            SELECT * FROM knowledge WHERE category = $1 ORDER BY updated_at DESC
        `, [category]);
        return result.rows;
    }

    // Store project
    async storeProject(name, description, options = {}) {
        const { status, tags, data } = options;

        const result = await this.pool.query(`
            INSERT INTO projects (name, description, status, tags, data)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (name) DO UPDATE SET
                description = EXCLUDED.description,
                status = COALESCE(EXCLUDED.status, projects.status),
                data = COALESCE(EXCLUDED.data, projects.data),
                updated_at = NOW()
            RETURNING id
        `, [name, description, status || 'active', tags || null, JSON.stringify(data || {})]);

        return { id: result.rows[0].id, name };
    }

    // Get project
    async getProject(name) {
        const result = await this.pool.query(`
            SELECT * FROM projects WHERE name = $1
        `, [name]);
        return result.rows[0] || null;
    }

    // List projects
    async listProjects(status) {
        let sql = 'SELECT * FROM projects';
        const params = [];

        if (status) {
            sql += ' WHERE status = $1';
            params.push(status);
        }

        sql += ' ORDER BY updated_at DESC';

        const result = await this.pool.query(sql, params);
        return result.rows;
    }

    // Store research
    async storeResearch(topic, findings, sources = [], quality = 0.5) {
        const result = await this.pool.query(`
            INSERT INTO research (topic, findings, sources, quality)
            VALUES ($1, $2, $3, $4)
            RETURNING id
        `, [topic, findings, sources, quality]);

        return { id: result.rows[0].id, topic };
    }

    // Get research by topic
    async getResearch(topic) {
        const result = await this.pool.query(`
            SELECT * FROM research WHERE topic ILIKE $1 ORDER BY quality DESC, created_at DESC
        `, [`%${topic}%`]);
        return result.rows;
    }

    // Store fact
    async storeFact(fact, options = {}) {
        const { category, source, confidence } = options;

        const result = await this.pool.query(`
            INSERT INTO facts (fact, category, source, confidence)
            VALUES ($1, $2, $3, $4)
            RETURNING id
        `, [fact, category || null, source || null, confidence || 0.5]);

        return { id: result.rows[0].id };
    }

    // Get facts
    async getFacts(category, limit = 20) {
        let sql = 'SELECT * FROM facts';
        const params = [];

        if (category) {
            sql += ' WHERE category = $1';
            params.push(category);
        }

        sql += ' ORDER BY confidence DESC, created_at DESC LIMIT $' + (params.length + 1);
        params.push(limit);

        const result = await this.pool.query(sql, params);
        return result.rows;
    }

    // Store user preference
    async setPreference(key, value) {
        const result = await this.pool.query(`
            INSERT INTO user_profile (key, value)
            VALUES ($1, $2)
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
            RETURNING id
        `, [key, value]);

        return { key, value };
    }

    // Get user preference
    async getPreference(key) {
        const result = await this.pool.query(`
            SELECT * FROM user_profile WHERE key = $1
        `, [key]);
        return result.rows[0] || null;
    }

    // Get all preferences
    async getAllPreferences() {
        const result = await this.pool.query(`
            SELECT * FROM user_profile ORDER BY key
        `);
        return result.rows;
    }

    // Get stats
    async getStats() {
        const [knowledge, projects, research, facts] = await Promise.all([
            this.pool.query('SELECT COUNT(*) as count FROM knowledge'),
            this.pool.query('SELECT COUNT(*) as count FROM projects'),
            this.pool.query('SELECT COUNT(*) as count FROM research'),
            this.pool.query('SELECT COUNT(*) as count FROM facts')
        ]);

        return {
            knowledge: parseInt(knowledge.rows[0].count),
            projects: parseInt(projects.rows[0].count),
            research: parseInt(research.rows[0].count),
            facts: parseInt(facts.rows[0].count)
        };
    }

    // Delete entry
    async delete(table, id) {
        const result = await this.pool.query(`
            DELETE FROM ${table} WHERE id = $1
        `, [id]);
        return { deleted: result.rowCount > 0 };
    }

    // Full-text search
    async fullTextSearch(query) {
        const result = await this.pool.query(`
            SELECT 'knowledge' as source, key, value FROM knowledge 
            WHERE key ILIKE $1 OR value ILIKE $1
            UNION
            SELECT 'research' as source, topic as key, findings as value FROM research 
            WHERE topic ILIKE $1 OR findings ILIKE $1
            UNION
            SELECT 'facts' as source, category as key, fact as value FROM facts 
            WHERE fact ILIKE $1
            ORDER BY source
        `, [`%${query}%`]);
        
        return result.rows;
    }
}

export default LongTermMemory;
