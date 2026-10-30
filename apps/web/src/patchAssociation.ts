export type FindingRef = {
  id: string;
  path: string;
  line?: number;
};

export type PatchRef = {
  path: string;
  finding_id?: string;
  old_text?: string;
  new_text?: string;
  reason?: string;
  scanner?: string;
  cwe?: string;
};

export type FindingPatchAssociation<P extends PatchRef = PatchRef> = {
  findingToPatch: Map<string, P>;
  findingToPatchIndex: Map<string, number>;
  patchToFindingId: Map<number, string>;
};

/**
 * Associate patches to findings unambiguously.
 *
 * Rules:
 * 1. Match patches to findings primarily by exact finding_id (strictly 1:1).
 * 2. For legacy patches without finding_id:
 *    - Fallback only when the relationship is unambiguous.
 *    - If scan has exactly 1 unassigned finding and 1 unassigned legacy patch on matching path.
 *    - Or if within a given file path, there is exactly 1 unassigned finding and 1 unassigned legacy patch.
 * 3. Never associate one patch with multiple findings.
 * 4. If association is ambiguous (e.g. multiple findings or multiple patches in the same file),
 *    leave the patch and finding unassigned rather than guessing.
 */
export function associateFindingsAndPatches<F extends FindingRef, P extends PatchRef>(
  findings: F[] = [],
  patches: P[] = []
): FindingPatchAssociation<P> {
  const findingToPatch = new Map<string, P>();
  const findingToPatchIndex = new Map<string, number>();
  const patchToFindingId = new Map<number, string>();

  const assignedFindingIds = new Set<string>();
  const assignedPatchIndices = new Set<number>();

  // Pass 1: Primary match by exact finding_id.
  // Must be strictly 1:1: exactly one finding with this ID and exactly one patch with this ID.
  for (const [patchIndex, patch] of patches.entries()) {
    const fid = patch.finding_id?.trim();
    if (!fid) continue;

    const matchingFindings = findings.filter((f) => f.id === fid);
    const patchesWithSameId = patches.filter((p) => p.finding_id?.trim() === fid);

    if (
      matchingFindings.length === 1 &&
      patchesWithSameId.length === 1 &&
      !assignedFindingIds.has(fid) &&
      !assignedPatchIndices.has(patchIndex)
    ) {
      const finding = matchingFindings[0];
      findingToPatch.set(finding.id, patch);
      findingToPatchIndex.set(finding.id, patchIndex);
      patchToFindingId.set(patchIndex, finding.id);
      assignedFindingIds.add(finding.id);
      assignedPatchIndices.add(patchIndex);
    }
  }

  // Pass 2: Unambiguous fallback for legacy patches WITHOUT finding_id.
  // Patches that specified a non-matching finding_id are NEVER eligible for fallback.
  const unassignedLegacyPatches: { patch: P; index: number }[] = [];
  for (const [patchIndex, patch] of patches.entries()) {
    if (!assignedPatchIndices.has(patchIndex) && !patch.finding_id?.trim()) {
      unassignedLegacyPatches.push({ patch, index: patchIndex });
    }
  }

  const unassignedFindings = findings.filter((f) => !assignedFindingIds.has(f.id));

  // Case 2A: Exactly one unassigned finding and one unassigned legacy patch in total.
  if (unassignedFindings.length === 1 && unassignedLegacyPatches.length === 1) {
    const { patch, index: patchIndex } = unassignedLegacyPatches[0];
    const finding = unassignedFindings[0];
    if (!patch.path || !finding.path || patch.path === finding.path) {
      findingToPatch.set(finding.id, patch);
      findingToPatchIndex.set(finding.id, patchIndex);
      patchToFindingId.set(patchIndex, finding.id);
      assignedFindingIds.add(finding.id);
      assignedPatchIndices.add(patchIndex);
    }
  } else if (unassignedFindings.length > 1 && unassignedLegacyPatches.length > 0) {
    // Case 2B: Multiple unassigned findings.
    // Match only if within a given file path there is EXACTLY 1 unassigned finding
    // and EXACTLY 1 unassigned legacy patch.
    for (const { patch, index: patchIndex } of unassignedLegacyPatches) {
      if (assignedPatchIndices.has(patchIndex) || !patch.path) continue;

      const candidates = unassignedFindings.filter(
        (f) => !assignedFindingIds.has(f.id) && f.path === patch.path
      );
      const patchesInSamePath = unassignedLegacyPatches.filter(
        (p) => !assignedPatchIndices.has(p.index) && p.patch.path === patch.path
      );

      if (candidates.length === 1 && patchesInSamePath.length === 1) {
        const finding = candidates[0];
        findingToPatch.set(finding.id, patch);
        findingToPatchIndex.set(finding.id, patchIndex);
        patchToFindingId.set(patchIndex, finding.id);
        assignedFindingIds.add(finding.id);
        assignedPatchIndices.add(patchIndex);
      }
    }
  }

  return {
    findingToPatch,
    findingToPatchIndex,
    patchToFindingId,
  };
}
