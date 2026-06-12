import { SaferExec } from '../npm/src/index.js';

const exec = new SaferExec()
  .binaryPath('/usr/local/bin/safer-exec-rt')
  .allowHosts('registry.npmjs.org')
  .traceCrypto()
  .enableAudit();

const events = [];
exec.on('audit', (entry) => {
  console.log('AUDIT EVENT:', JSON.stringify(entry));
  events.push(entry);
});

console.log('Starting execution...');
try {
  const result = await exec.run('curl', ['-sI', 'https://registry.npmjs.org/']);
  console.log('Execution finished. Exit code:', result.exitCode);
  console.log('Audit events count:', events.length);
  console.log('Libraries:', JSON.stringify(result.crypto?.libraries));
  console.log('Ciphers:', JSON.stringify(result.crypto?.ciphers));
} catch (err) {
  console.error('Error during execution:', err);
}
