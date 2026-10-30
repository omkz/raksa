import test from 'node:test';
import assert from 'node:assert';
import { associateFindingsAndPatches, type FindingRef, type PatchRef } from './patchAssociation.ts';

test('1. Unique exact finding_id matches findings and patches 1:1', () => {
  const findings: FindingRef[] = [
    { id: 'sql-1', path: 'app.py' },
    { id: 'xss-1', path: 'src/view.js' },
  ];
  const patches: PatchRef[] = [
    { finding_id: 'xss-1', path: 'src/view.js', reason: 'Escape HTML' },
    { finding_id: 'sql-1', path: 'app.py', reason: 'Parameterize SQL' },
  ];

  const result = associateFindingsAndPatches(findings, patches);

  assert.strictEqual(result.findingToPatch.get('sql-1')?.reason, 'Parameterize SQL');
  assert.strictEqual(result.findingToPatchIndex.get('sql-1'), 1);
  assert.strictEqual(result.patchToFindingId.get(1), 'sql-1');

  assert.strictEqual(result.findingToPatch.get('xss-1')?.reason, 'Escape HTML');
  assert.strictEqual(result.findingToPatchIndex.get('xss-1'), 0);
  assert.strictEqual(result.patchToFindingId.get(0), 'xss-1');
});

test('2. Legacy single finding and single patch match unambiguously when path matches (demo proof)', () => {
  const findings: FindingRef[] = [
    { id: 'demo-sqli', path: 'app.py' },
  ];
  const patches: PatchRef[] = [
    { path: 'app.py', reason: 'Use parameterized query' },
  ];

  const result = associateFindingsAndPatches(findings, patches);

  assert.strictEqual(result.findingToPatch.get('demo-sqli')?.reason, 'Use parameterized query');
  assert.strictEqual(result.findingToPatchIndex.get('demo-sqli'), 0);
  assert.strictEqual(result.patchToFindingId.get(0), 'demo-sqli');
});

test('3. Legacy single finding and single patch do not match if paths conflict', () => {
  const findings: FindingRef[] = [
    { id: 'f1', path: 'app.py' },
  ];
  const patches: PatchRef[] = [
    { path: 'other.py', reason: 'Some change' },
  ];

  const result = associateFindingsAndPatches(findings, patches);

  assert.strictEqual(result.findingToPatch.has('f1'), false);
  assert.strictEqual(result.patchToFindingId.has(0), false);
});

test('4. Multi-file legacy patch associates only with the unambiguous matching file, never with other findings', () => {
  const findings: FindingRef[] = [
    { id: 'f1', path: 'app.py' },
    { id: 'f2', path: 'db.py' },
    { id: 'f3', path: 'utils.py' },
  ];
  const patches: PatchRef[] = [
    { path: 'app.py', reason: 'Fix SQL in app.py' },
  ];

  const result = associateFindingsAndPatches(findings, patches);

  // f1 matches app.py unambiguously
  assert.strictEqual(result.findingToPatch.get('f1')?.reason, 'Fix SQL in app.py');
  assert.strictEqual(result.findingToPatchIndex.get('f1'), 0);
  assert.strictEqual(result.patchToFindingId.get(0), 'f1');

  // f2 and f3 must NEVER be associated with the single patch
  assert.strictEqual(result.findingToPatch.has('f2'), false);
  assert.strictEqual(result.findingToPatch.has('f3'), false);
  assert.strictEqual(result.findingToPatchIndex.has('f2'), false);
  assert.strictEqual(result.findingToPatchIndex.has('f3'), false);
});

test('5. Ambiguous legacy patch: multiple findings in the same file leave patch unassigned', () => {
  const findings: FindingRef[] = [
    { id: 'f1', path: 'app.py', line: 10 },
    { id: 'f2', path: 'app.py', line: 55 },
  ];
  const patches: PatchRef[] = [
    { path: 'app.py', reason: 'Generic patch for app.py' },
  ];

  const result = associateFindingsAndPatches(findings, patches);

  // Ambiguous: neither finding claims the patch
  assert.strictEqual(result.findingToPatch.has('f1'), false);
  assert.strictEqual(result.findingToPatch.has('f2'), false);
  assert.strictEqual(result.findingToPatchIndex.has('f1'), false);
  assert.strictEqual(result.findingToPatchIndex.has('f2'), false);

  // Patch is unassigned
  assert.strictEqual(result.patchToFindingId.has(0), false);
});

test('6. Ambiguous legacy patches: multiple legacy patches for one file leave all unassigned', () => {
  const findings: FindingRef[] = [
    { id: 'f1', path: 'app.py' },
  ];
  const patches: PatchRef[] = [
    { path: 'app.py', reason: 'Patch A' },
    { path: 'app.py', reason: 'Patch B' },
  ];

  const result = associateFindingsAndPatches(findings, patches);

  assert.strictEqual(result.findingToPatch.has('f1'), false);
  assert.strictEqual(result.patchToFindingId.has(0), false);
  assert.strictEqual(result.patchToFindingId.has(1), false);
});

test('7. Unknown finding_id does not fall back to path matching', () => {
  const findings: FindingRef[] = [
    { id: 'f1', path: 'app.py' },
  ];
  const patches: PatchRef[] = [
    { finding_id: 'non-existent-id', path: 'app.py', reason: 'Fix' },
  ];

  const result = associateFindingsAndPatches(findings, patches);

  assert.strictEqual(result.findingToPatch.has('f1'), false);
  assert.strictEqual(result.patchToFindingId.has(0), false);
});

test('8. Exact match takes precedence, allowing remaining unassigned finding and legacy patch to resolve unambiguously', () => {
  const findings: FindingRef[] = [
    { id: 'f1', path: 'app.py', line: 10 },
    { id: 'f2', path: 'app.py', line: 55 },
  ];
  const patches: PatchRef[] = [
    { finding_id: 'f1', path: 'app.py', reason: 'Fix for line 10' },
    { path: 'app.py', reason: 'Fix for line 55 (legacy)' },
  ];

  const result = associateFindingsAndPatches(findings, patches);

  // f1 matched Patch 0 by exact id
  assert.strictEqual(result.findingToPatch.get('f1')?.reason, 'Fix for line 10');
  assert.strictEqual(result.findingToPatchIndex.get('f1'), 0);
  assert.strictEqual(result.patchToFindingId.get(0), 'f1');

  // f2 is now the only unassigned finding in app.py, and Patch 1 is the only legacy patch
  assert.strictEqual(result.findingToPatch.get('f2')?.reason, 'Fix for line 55 (legacy)');
  assert.strictEqual(result.findingToPatchIndex.get('f2'), 1);
  assert.strictEqual(result.patchToFindingId.get(1), 'f2');
});

test('9. Malformed scan with duplicate finding_id across patches is treated as ambiguous', () => {
  const findings: FindingRef[] = [
    { id: 'f1', path: 'app.py' },
  ];
  const patches: PatchRef[] = [
    { finding_id: 'f1', path: 'app.py', reason: 'Proposal 1' },
    { finding_id: 'f1', path: 'app.py', reason: 'Proposal 2' },
  ];

  const result = associateFindingsAndPatches(findings, patches);

  assert.strictEqual(result.findingToPatch.has('f1'), false);
  assert.strictEqual(result.patchToFindingId.has(0), false);
  assert.strictEqual(result.patchToFindingId.has(1), false);
});

test('10. Empty or undefined inputs return empty maps safely', () => {
  const result1 = associateFindingsAndPatches([], []);
  assert.strictEqual(result1.findingToPatch.size, 0);
  assert.strictEqual(result1.findingToPatchIndex.size, 0);
  assert.strictEqual(result1.patchToFindingId.size, 0);

  const result2 = associateFindingsAndPatches(undefined, undefined);
  assert.strictEqual(result2.findingToPatch.size, 0);
  assert.strictEqual(result2.findingToPatchIndex.size, 0);
  assert.strictEqual(result2.patchToFindingId.size, 0);
});

test('11. Legacy fallback rejects association if patch path is empty or whitespace', () => {
  const findings: FindingRef[] = [
    { id: 'f1', path: 'app.py' },
  ];
  const patchesEmpty: PatchRef[] = [
    { path: '', reason: 'Empty path patch' },
  ];
  const resultEmpty = associateFindingsAndPatches(findings, patchesEmpty);
  assert.strictEqual(resultEmpty.findingToPatch.has('f1'), false);
  assert.strictEqual(resultEmpty.patchToFindingId.has(0), false);

  const patchesWhitespace: PatchRef[] = [
    { path: '   ', reason: 'Whitespace path patch' },
  ];
  const resultWhitespace = associateFindingsAndPatches(findings, patchesWhitespace);
  assert.strictEqual(resultWhitespace.findingToPatch.has('f1'), false);
  assert.strictEqual(resultWhitespace.patchToFindingId.has(0), false);
});

test('12. Legacy fallback rejects association if finding path is empty or whitespace', () => {
  const findings: FindingRef[] = [
    { id: 'f1', path: '' },
  ];
  const patches: PatchRef[] = [
    { path: 'app.py', reason: 'Patch with path' },
  ];
  const result = associateFindingsAndPatches(findings, patches);
  assert.strictEqual(result.findingToPatch.has('f1'), false);
  assert.strictEqual(result.patchToFindingId.has(0), false);
});

test('13. Legacy fallback rejects association if both paths are empty', () => {
  const findings: FindingRef[] = [
    { id: 'f1', path: '' },
  ];
  const patches: PatchRef[] = [
    { path: '', reason: 'Both empty' },
  ];
  const result = associateFindingsAndPatches(findings, patches);
  assert.strictEqual(result.findingToPatch.has('f1'), false);
  assert.strictEqual(result.patchToFindingId.has(0), false);
});

test('14. Legacy fallback rejects association if paths mismatch', () => {
  const findings: FindingRef[] = [
    { id: 'f1', path: 'server.py' },
  ];
  const patches: PatchRef[] = [
    { path: 'client.py', reason: 'Mismatch' },
  ];
  const result = associateFindingsAndPatches(findings, patches);
  assert.strictEqual(result.findingToPatch.has('f1'), false);
  assert.strictEqual(result.patchToFindingId.has(0), false);
});

test('15. Legacy fallback succeeds when both paths are non-empty and exactly equal', () => {
  const findings: FindingRef[] = [
    { id: 'f1', path: 'src/services/auth.py' },
  ];
  const patches: PatchRef[] = [
    { path: 'src/services/auth.py', reason: 'Valid exact path match' },
  ];
  const result = associateFindingsAndPatches(findings, patches);
  assert.strictEqual(result.findingToPatch.get('f1')?.reason, 'Valid exact path match');
  assert.strictEqual(result.findingToPatchIndex.get('f1'), 0);
  assert.strictEqual(result.patchToFindingId.get(0), 'f1');
});

