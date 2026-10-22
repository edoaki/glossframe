import { Hono } from "hono";
import type { AppEnv } from "../env";
import {
  checkLoginRateLimit,
  clearSession,
  clientIp,
  createOwner,
  createSession,
  deleteOtherSessions,
  getOwner,
  readSession,
  recordLoginAttempt,
  requireAuth,
  updateOwnerPassword,
  verifyPassword,
} from "../auth";
import { changePasswordSchema, loginSchema, setupSchema } from "../../shared/schemas";
import { parseBody } from "../validate";
import { ApiError } from "../errors";

export const authRoutes = new Hono<AppEnv>();

authRoutes.get("/status", async (c) => {
  const owner = await getOwner(c.env);
  const session = owner.exists ? await readSession(c) : null;
  const setupAllowed = c.env.OWNER_SETUP_DISABLED !== "true";
  return c.json({
    setupRequired: !owner.exists && setupAllowed,
    setupDisabled: !owner.exists && !setupAllowed,
    authenticated: Boolean(session),
    appName: c.env.APP_NAME ?? "GlossFrame",
    sessionExpiresAt: session?.expiresAt ?? null,
  });
});

authRoutes.post("/setup", async (c) => {
  if (c.env.OWNER_SETUP_DISABLED === "true") {
    throw new ApiError(403, "SETUP_DISABLED", "このアプリは所有者専用です。設定済みのパスワードで開いてください。");
  }
  const owner = await getOwner(c.env);
  if (owner.exists) {
    throw new ApiError(409, "ALREADY_SETUP", "このインスタンスは既にセットアップ済みです。");
  }
  const body = await parseBody(c, setupSchema);
  try {
    await createOwner(c.env, body.password);
  } catch (error) {
    const again = await getOwner(c.env);
    if (again.exists) {
      throw new ApiError(409, "ALREADY_SETUP", "このインスタンスは既にセットアップ済みです。");
    }
    throw error;
  }
  await createSession(c, {
    userAgent: c.req.header("user-agent"),
    ip: clientIp(c),
  });
  return c.json({ ok: true });
});

authRoutes.post("/login", async (c) => {
  const owner = await getOwner(c.env);
  if (!owner.exists) {
    throw new ApiError(428, "SETUP_REQUIRED", "先に初期設定を行ってください。");
  }
  const limit = await checkLoginRateLimit(c);
  if (!limit.allowed) {
    c.header("Retry-After", String(limit.retryAfter));
    throw new ApiError(
      429,
      "TOO_MANY_ATTEMPTS",
      "ログイン試行が多すぎます。しばらく待ってからお試しください。",
    );
  }
  const body = await parseBody(c, loginSchema);
  const ok = await verifyPassword(
    body.password,
    owner.passwordHash ?? "",
    owner.salt ?? "",
    owner.iterations ?? 100_000,
  );
  if (!ok) {
    await recordLoginAttempt(c, false);
    // Slow down automated guessing without revealing whether the owner exists.
    await new Promise((resolve) => setTimeout(resolve, 300));
    throw new ApiError(401, "INVALID_PASSWORD", "パスワードが違います。");
  }
  await recordLoginAttempt(c, true);
  await createSession(c, {
    userAgent: c.req.header("user-agent"),
    ip: clientIp(c),
  });
  return c.json({ ok: true });
});

authRoutes.post("/logout", async (c) => {
  await clearSession(c);
  return c.json({ ok: true });
});

authRoutes.post("/password", requireAuth(), async (c) => {
  const body = await parseBody(c, changePasswordSchema);
  const owner = await getOwner(c.env);
  if (!owner.exists) {
    throw new ApiError(409, "SETUP_REQUIRED", "初期設定が完了していません。");
  }
  const ok = await verifyPassword(
    body.currentPassword,
    owner.passwordHash ?? "",
    owner.salt ?? "",
    owner.iterations ?? 100_000,
  );
  if (!ok) {
    throw new ApiError(401, "INVALID_PASSWORD", "現在のパスワードが違います。");
  }
  await updateOwnerPassword(c.env, body.newPassword);
  const session = c.get("session");
  await deleteOtherSessions(c, session.id);
  return c.json({ ok: true });
});
