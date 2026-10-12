/**
 * Unit tests for the runner module (runner.js).
 *
 * @module runner_test
 */

import { describe, it } from 'node:test';
import strict from 'node:assert/strict';
import { dirname } from 'node:path';
import { resolveBinaryPath, run, runPipe, readStructuredFile, createReportParser, engineSpawnOptions, REPORT_FD } from './runner.js';

const baseReadPaths = process.platform === 'darwin'
  ? ['/bin', '/usr', '/System', '/dev', '/private', dirname(process.execPath)]
  : ['/bin', '/usr', '/lib', '/lib64', dirname(process.execPath)];

function createConfig(overrides) {
  return {
    env: {},
    readPaths: baseReadPaths,
    writePaths: [],
    allowHosts: [],
    allowIPs: [],
    disableNetwork: false,
    maxMemoryMB: 0,
    workingDir: '',
    ...overrides
  };
}

describe('run', () => {
  it('should execute a simple echo command', async () => {
    const result = await run(createConfig({ cmd: 'echo', args: ['hello from test'] }));
    strict.equal(result.exitCode, 0, `should exit with code 0. STDERR: ${result.stderr}`);
    strict.ok(result.stdout.includes('hello from test'));
  });

  it('should capture stderr', async () => {
    const result = await run(createConfig({ cmd: 'sh', args: ['-c', 'echo "stderr message" >&2'] }));
    strict.equal(result.exitCode, 0);
    strict.ok(result.stderr.includes('stderr message'));
  });

  it('should return non-zero exit code for failing command', async () => {
    const result = await run(createConfig({ cmd: 'sh', args: ['-c', 'exit 42'] }));
    strict.equal(result.exitCode, 42);
  });

  it('should pass environment variables', async () => {
    const result = await run(createConfig({ cmd: 'sh', args: ['-c', 'echo $TEST_VAR'], env: { TEST_VAR: 'sandboxed_value' } }));
    strict.equal(result.exitCode, 0);
    strict.ok(result.stdout.includes('sandboxed_value'));
  });
});

describe('runPipe', () => {
  it('should stream real-time stdout and exit correctly', async () => {
    let output = '';
    const stdoutMock = {
      write(chunk) {
        output += chunk.toString();
      }
    };
    const result = await runPipe(
      createConfig({ cmd: 'echo', args: ['pipe test line'] }),
      { stdout: stdoutMock }
    );
    strict.equal(result.exitCode, 0);
    strict.ok(output.includes('pipe test line'));
  });
});
describe('report channel', () => {
  it('splits audit entries and results across chunk boundaries', () => {
    const audits = [];
    const parser = createReportParser((e) => audits.push(e));
    const lines = [
      '{"report":1}',
      '{"audit":{"type":"lib-load","target":"/lib/libc.so.6"}}',
      '{"audit":{"type":"nothing"}}',
      'not json',
      '{"result":"FSDIFF","data":{"added":[{"path":"/tmp/a"}]}}',
      '{"result":"PROFILE","data":"(version 1)\\n(deny default)"}',
      '{"result":"CRYPTO","data":{"ciphers":[]}}',
      '{"result":"UNKNOWN","data":1}',
    ].join('\n');
    for (let i = 0; i < lines.length; i += 7) {
      parser.push(Buffer.from(lines.slice(i, i + 7)));
    }
    parser.end();
    strict.equal(parser.opened, true);
    strict.deepEqual(audits, [{ type: 'lib-load', target: '/lib/libc.so.6' }]);
    strict.deepEqual(parser.results.fsDiff, { added: [{ path: '/tmp/a' }] });
    strict.equal(parser.results.profile, '(version 1)\n(deny default)');
    strict.deepEqual(parser.results.crypto, { ciphers: [] });
    strict.equal(parser.results.learnedPolicy, null);
  });

  it('notices an engine that never opened the channel', () => {
    const parser = createReportParser(() => {});
    parser.push('{"audit":{"type":"lib-load","target":"/x"}}\n');
    parser.end();
    strict.equal(parser.opened, false);
  });

  it('passes the channel to the engine as stdio[3]', () => {
    strict.equal(REPORT_FD, 3);
    strict.equal(engineSpawnOptions().stdio[REPORT_FD], 'pipe');
  });
});
