#!/usr/bin/env node
// Magnitude Browser CLI - Quick browser research tool

import { BrowserAgent } from '@magnitudedev/browser-agent';
import { z } from 'zod';

const args = process.argv.slice(2);
const query = args[0];
const headless = args.includes('--headless');

if (!query) {
    console.log('Usage: magnitude-browser "your research query" [--headless]');
    console.log('');
    console.log('Examples:');
    console.log('  magnitude-browser "latest AI news"');
    console.log('  magnitude-browser "Python tutorials" --headless');
    process.exit(1);
}

console.log(`🔍 Magnitude researching: "${query}"`);
console.log(`   Mode: ${headless ? 'headless' : 'visible'}\n`);

const agent = new BrowserAgent({
    llm: 'claude-sonnet-4',
    apiKey: process.env.ANTHROPIC_API_KEY,
    headless
});

try {
    await agent.act(query);
    
    console.log('\n✅ Task completed!');
    console.log('   Browser will remain open for inspection.');
    console.log('   Press Ctrl+C to close.');
    
    process.on('SIGINT', async () => {
        await agent.close();
        process.exit(0);
    });
} catch (error) {
    console.error('❌ Error:', error.message);
    await agent.close();
    process.exit(1);
}
