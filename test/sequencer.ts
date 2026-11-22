import { BaseSequencer, type TestSpecification } from "vitest/node";

/** Longest files first (measured in CI), so they overlap with the rest instead of trailing at the end. */
const LONG = ["v2-mutation", "v2-failures", "v2-recovery", "security", "v1-sidecar", "v1-policy", "v2-audit", "api-session"];
const rank = (f: string) => {
  const i = LONG.findIndex((n) => f.endsWith(`/${n}.test.ts`));
  return i === -1 ? LONG.length : i;
};

export default class LongFirstSequencer extends BaseSequencer {
  override async sort(files: TestSpecification[]): Promise<TestSpecification[]> {
    const sorted = await super.sort(files);
    return [...sorted].sort((a, b) => rank(a.moduleId) - rank(b.moduleId));
  }
}
