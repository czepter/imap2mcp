import { randomBytes, scrypt, timingSafeEqual, type ScryptOptions } from "crypto";

const N = 1 << 15, R = 8, P = 1, KEYLEN = 64;
const opts: ScryptOptions = { N, r: R, p: P, maxmem: 128 * N * R * 2 };

function derive(password: string, salt: Buffer, o: ScryptOptions, keylen: number): Promise<Buffer> {
  return new Promise((res, rej) => scrypt(password, salt, keylen, o, (e, k) => (e ? rej(e) : res(k))));
}

/** Format: scrypt$N$r$p$<b64 salt>$<b64 hash> */
export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16);
  const h = await derive(password, salt, opts, KEYLEN);
  return `scrypt$${N}$${R}$${P}$${salt.toString("base64")}$${h.toString("base64")}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const p = stored.split("$");
  if (p.length !== 6 || p[0] !== "scrypt") return false;
  const n = Number(p[1]), r = Number(p[2]), pp = Number(p[3]);
  if (![n, r, pp].every(Number.isInteger) || n > 1 << 20) return false;
  const expected = Buffer.from(p[5], "base64");
  const got = await derive(password, Buffer.from(p[4], "base64"), { N: n, r, p: pp, maxmem: 128 * n * r * 2 }, expected.length);
  return got.length === expected.length && timingSafeEqual(got, expected);
}
