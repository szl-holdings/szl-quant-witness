import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { appendObservationIndex, OBSERVATION_HEADER } from '../observation-index.mjs';

function directory(t) {
  const root = fs.mkdtempSync(join(tmpdir(), 'szl-observation-index-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}

test('new index has one header and all later rows preserve its bytes', (t) => {
  const path = join(directory(t), 'OBSERVATIONS.md');
  appendObservationIndex(path, '| first |\n');
  appendObservationIndex(path, '| second |\n');
  assert.equal(fs.readFileSync(path, 'utf8'), OBSERVATION_HEADER + '| first |\n| second |\n');
});

test('existing nonempty index is append-only, and an empty index is initialized', (t) => {
  const root = directory(t);
  const existing = join(root, 'existing.md');
  fs.writeFileSync(existing, 'historical bytes\n');
  appendObservationIndex(existing, 'new row\n');
  assert.equal(fs.readFileSync(existing, 'utf8'), 'historical bytes\nnew row\n');
  const empty = join(root, 'empty.md');
  fs.writeFileSync(empty, '');
  appendObservationIndex(empty, 'first row\n');
  assert.equal(fs.readFileSync(empty, 'utf8'), OBSERVATION_HEADER + 'first row\n');
});

test('hard-linked aliases are refused without modifying the target', (t) => {
  const root = directory(t);
  const target = join(root, 'target.md');
  const alias = join(root, 'alias.md');
  fs.writeFileSync(target, 'do not modify\n');
  fs.linkSync(target, alias);
  assert.throws(() => appendObservationIndex(alias, 'injected\n'), /regular/);
  assert.equal(fs.readFileSync(target, 'utf8'), 'do not modify\n');
});

test('symlinks are refused without modifying the target', (t) => {
  const root = directory(t);
  const target = join(root, 'target.md');
  const alias = join(root, 'alias.md');
  fs.writeFileSync(target, 'do not modify\n');
  try { fs.symlinkSync(target, alias); } catch (error) {
    if (process.platform === 'win32' && error.code === 'EPERM') {
      t.skip('Windows symlink privilege unavailable; canonical Linux CI must run this test');
      return;
    }
    throw error;
  }
  assert.throws(() => appendObservationIndex(alias, 'injected\n'));
  assert.equal(fs.readFileSync(target, 'utf8'), 'do not modify\n');
  const missing = join(root, 'must-not-create.md');
  const dangling = join(root, 'dangling.md');
  fs.symlinkSync(missing, dangling);
  assert.throws(() => appendObservationIndex(dangling, 'injected\n'));
  assert.equal(fs.existsSync(missing), false);
});

test('directories are rejected', (t) => {
  assert.throws(() => appendObservationIndex(directory(t), 'injected\n'));
});

test('identity mismatch fails before writing and always closes the descriptor', (t) => {
  const path = join(directory(t), 'index.md');
  fs.writeFileSync(path, 'preserve\n');
  const originalStat = fs.lstatSync;
  const originalClose = fs.closeSync;
  let closes = 0;
  fs.lstatSync = (...args) => {
    const value = originalStat(...args);
    value.ino += 1n;
    return value;
  };
  fs.closeSync = (...args) => { closes += 1; return originalClose(...args); };
  try {
    assert.throws(() => appendObservationIndex(path, 'injected\n'), /regular/);
  } finally {
    fs.lstatSync = originalStat;
    fs.closeSync = originalClose;
  }
  assert.equal(closes, 1);
  assert.equal(fs.readFileSync(path, 'utf8'), 'preserve\n');
});

test('write errors still close the opened descriptor', (t) => {
  const path = join(directory(t), 'index.md');
  fs.writeFileSync(path, 'preserve\n');
  const originalWrite = fs.writeFileSync;
  const originalClose = fs.closeSync;
  let closes = 0;
  fs.writeFileSync = () => { throw new Error('simulated write failure'); };
  fs.closeSync = (...args) => { closes += 1; return originalClose(...args); };
  try {
    assert.throws(() => appendObservationIndex(path, 'injected\n'), /simulated write failure/);
  } finally {
    fs.writeFileSync = originalWrite;
    fs.closeSync = originalClose;
  }
  assert.equal(closes, 1);
  assert.equal(fs.readFileSync(path, 'utf8'), 'preserve\n');
});

test('replacement after validation cannot redirect the descriptor write', (t) => {
  const root = directory(t);
  const path = join(root, 'index.md');
  const moved = join(root, 'original.md');
  fs.writeFileSync(path, 'original\n');
  const originalStat = fs.lstatSync;
  let swapped = false;
  fs.lstatSync = (...args) => {
    const value = originalStat(...args);
    fs.renameSync(path, moved);
    fs.writeFileSync(path, 'replacement must stay unchanged\n');
    swapped = true;
    return value;
  };
  try {
    appendObservationIndex(path, 'new row\n');
  } finally {
    fs.lstatSync = originalStat;
  }
  assert.equal(swapped, true);
  assert.equal(fs.readFileSync(path, 'utf8'), 'replacement must stay unchanged\n');
  assert.equal(fs.readFileSync(moved, 'utf8'), 'original\nnew row\n');
});
