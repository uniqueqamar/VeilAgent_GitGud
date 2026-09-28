#!/usr/bin/env node
/**
 * Veil Agent - Phase 4 Vision Evaluation Runner
 * Calls python eval/run_vision.py to execute the full evaluation suite.
 */

const { spawn } = require('child_process');
const path = require('path');

const scriptPath = path.resolve(__dirname, 'run_vision.py');
const py = spawn('python', [scriptPath], { stdio: 'inherit' });

py.on('close', (code) => {
  process.exit(code);
});
