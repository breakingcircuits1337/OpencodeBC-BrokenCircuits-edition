// Knowledge Base CLI

import readline from 'readline';
import KnowledgeBase from './index.js';

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

const kb = new KnowledgeBase();

async function main() {
    const args = process.argv.slice(2);
    const command = args[0];

    // Initialize
    await kb.initialize();

    switch (command) {
        case 'learn':
            if (!args[1]) {
                console.log('Usage: learn <key> <value> [--permanent] [--category=...]');
                process.exit(1);
            }
            
            const key = args[1];
            const value = args.slice(2, args.indexOf('--') > 0 ? args.indexOf('--') : undefined).join(' ') || args[2];
            const permanent = args.includes('--permanent');
            const category = args.find(a => a.startsWith('--category='))?.split('=')[1];
            
            const result = await kb.learn(key, value, { permanent, category });
            console.log('✅ Learned:', result);
            break;

        case 'recall':
            if (!args[1]) {
                console.log('Usage: recall <key>');
                process.exit(1);
            }
            
            const recallResult = await kb.recall(args[1]);
            console.log(recallResult || 'Not found');
            break;

        case 'search':
            if (!args[1]) {
                console.log('Usage: search <query>');
                process.exit(1);
            }
            
            const searchResults = await kb.search(args.slice(1).join(' '));
            console.log('Search results:');
            console.log(JSON.stringify(searchResults, null, 2));
            break;

        case 'project':
            const projCmd = args[1];
            
            if (projCmd === 'create') {
                const name = args[2];
                const desc = args.slice(3).join(' ');
                const result = await kb.createProject(name, desc);
                console.log('✅ Project created:', result);
            } else if (projCmd === 'get') {
                const proj = await kb.getProject(args[2]);
                console.log(proj || 'Not found');
            } else if (projCmd === 'list') {
                const projects = await kb.listProjects(args[2]); // status filter
                console.log(`Found ${projects.length} projects:`);
                projects.forEach(p => console.log(`  - ${p.name} (${p.status})`));
            } else {
                console.log('Usage: project <create|get|list> [name] [description]');
            }
            break;

        case 'research':
            const topic = args.slice(1).join(' ');
            
            const research = await kb.getResearch(topic);
            console.log(`Found ${research.length} research entries:`);
            research.forEach(r => {
                console.log(`\n📄 ${r.topic}`);
                console.log(`   Quality: ${r.quality}`);
                console.log(`   Findings: ${r.findings?.slice(0, 200)}...`);
            });
            break;

        case 'facts':
            const factsCategory = args[1];
            const facts = await kb.getFacts(factsCategory);
            console.log(`Found ${facts.length} facts:`);
            facts.forEach(f => console.log(`  - ${f.fact}`));
            break;

        case 'stats':
            const stats = await kb.getStats();
            console.log('📊 Knowledge Base Stats');
            console.log('========================');
            console.log(`Short-term (Redis):`);
            console.log(`   Connected: ${stats.shortTerm.connected}`);
            console.log(`   Keys: ${stats.shortTerm.keys}`);
            console.log(`\nLong-term (PostgreSQL):`);
            console.log(`   Knowledge: ${stats.longTerm.knowledge}`);
            console.log(`   Projects: ${stats.longTerm.projects}`);
            console.log(`   Research: ${stats.longTerm.research}`);
            console.log(`   Facts: ${stats.longTerm.facts}`);
            break;

        case 'recent':
            const recent = await kb.getRecentLearnings();
            console.log('Recent learnings:');
            recent.forEach(r => console.log(`  - ${r.key}: ${JSON.stringify(r).slice(0, 50)}`));
            break;

        case 'context':
            const sessionId = args[1] || 'default';
            const messages = await kb.getHistory(sessionId, 10);
            console.log(`Conversation history (${sessionId}):`);
            messages.forEach(m => {
                console.log(`  [${m.role}]: ${m.content?.slice(0, 80)}`);
            });
            break;

        case 'clear':
            const cleared = await kb.clearShortTerm();
            console.log('Cleared:', cleared);
            break;

        case 'interactive':
            console.log('🧠 Interactive Learning Mode');
            console.log('Type "quit" to exit\n');
            
            const interact = () => {
                rl.question('You: ', async (input) => {
                    if (input.toLowerCase() === 'quit') {
                        console.log('Goodbye!');
                        await kb.disconnect();
                        process.exit(0);
                    }

                    // Learn from input
                    await kb.learn(`user_input_${Date.now()}`, input, { permanent: false });
                    
                    // Search for related
                    const results = await kb.search(input);
                    if (results.longTerm.length > 0) {
                        console.log('💡 Related knowledge:');
                        results.longTerm.slice(0, 3).forEach(r => {
                            console.log(`   - ${r.key}: ${r.value?.slice(0, 100)}`);
                        });
                    }
                    
                    interact();
                });
            };
            
            interact();
            return;

        default:
            console.log(`
🧠 Knowledge Base CLI
====================

Usage: node cli.js <command> [options]

Commands:
  learn <key> <value> [--permanent]    Learn something (use --permanent for long-term)
  recall <key>                       Recall stored knowledge
  search <query>                     Search all knowledge
  project create <name> <desc>       Create a project
  project get <name>                 Get project details
  project list [status]              List all projects
  research <topic>                   Get research on topic
  facts [category]                   Get facts by category
  stats                              Show knowledge base stats
  recent                             Show recent learnings
  context [session]                   Get conversation history
  clear                              Clear short-term memory
  interactive                        Start interactive learning mode

Examples:
  node cli.js learn "my name" "Sarah"
  node cli.js learn "project" "Magnitude v2.8" --permanent --category=projects
  node cli.js recall "my name"
  node cli.js search "Magnitude"
  node cli.js project create "Magnitude" "LLM self-improvement framework"
  node cli.js interactive
`);
    }

    await kb.disconnect();
}

main().catch(console.error);
