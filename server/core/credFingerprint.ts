import { createHash } from "node:crypto";

const sha8 = (s: string): string => createHash("sha256").update(s, "utf8").digest("hex").slice(0, 8);

/** Non-reversible diagnostic summary of a credential pair; never contains the user or password themselves. */
export function credFingerprint(user: string, pass: string): Record<string, string | number | boolean> {
  return {
    user_len: user.length,
    user_sha: sha8(user),
    pass_len: pass.length,
    pass_sha: sha8(pass),
    user_trim: user !== user.trim(),
    pass_trim: pass !== pass.trim(),
    pass_ascii: [...pass].every((c) => c.codePointAt(0)! < 0x80),
  };
}
