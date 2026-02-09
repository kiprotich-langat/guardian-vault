/**
 * Guardian Vault - Test Runner
 * 
 * Run this file to test the prompt analyzer with known attack vectors
 */

import { PromptAnalyzer } from './analyzer/prompt-analyzer';

async function main() {
  console.log('╔══════════════════════════════════════════════════════════════╗');
  console.log('║          Guardian Vault - Prompt Analyzer Test Suite         ║');
  console.log('╚══════════════════════════════════════════════════════════════╝\n');
  
  await PromptAnalyzer.runTests();
}

main().catch(console.error);
