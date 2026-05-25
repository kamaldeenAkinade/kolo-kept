"use client";

import { useState, useEffect, Suspense } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { getPasswordStrengthLabel } from "@/lib/password";

function ConfirmForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const tokenFromUrl = searchParams.get("token") ?? "";

  const [token, setToken] = useState(tokenFromUrl);
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);

  useEffect(() => {
    if (tokenFromUrl) setToken(tokenFromUrl);
  }, [tokenFromUrl]);

  const strength = password ? getPasswordStrengthLabel(password) : null;

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");

    if (password !== confirm) {
      setError("Passwords do not match.");
      return;
    }

    setLoading(true);
    try {
      const res = await fetch("/api/auth/reset-password/confirm", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token, password }),
      });

      const data = await res.json();

      if (!res.ok) {
        setError(data.error ?? "Something went wrong.");
        return;
      }

      setSuccess(true);
      setTimeout(() => router.push("/dashboard"), 1500);
    } catch {
      setError("Unable to connect. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  if (success) {
    return (
      <div className="card text-center">
        <div className="w-12 h-12 rounded-full bg-brand-100 flex items-center justify-center mx-auto mb-4">
          <svg className="w-6 h-6 text-brand-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
          </svg>
        </div>
        <h2 className="text-xl font-semibold text-gray-900">Password updated!</h2>
        <p className="text-sm text-gray-600 mt-2">Redirecting you to your dashboard…</p>
      </div>
    );
  }

  return (
    <div className="card">
      <h2 className="text-xl font-semibold text-gray-900 mb-6">Set a new password</h2>

      {error && <p className="error-msg mb-4">{error}</p>}

      <form onSubmit={handleSubmit} className="space-y-4">
        {!tokenFromUrl && (
          <div>
            <label htmlFor="token" className="block text-sm font-medium text-gray-700 mb-1">
              Reset token
            </label>
            <input
              id="token"
              type="text"
              required
              value={token}
              onChange={(e) => setToken(e.target.value)}
              className="input font-mono"
              placeholder="Paste your reset token"
            />
          </div>
        )}

        <div>
          <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-1">
            New password
          </label>
          <input
            id="password"
            type="password"
            autoComplete="new-password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="input"
            placeholder="At least 12 characters"
          />
          {password && strength && (
            <div className="mt-2">
              <div className="h-1.5 bg-gray-200 rounded-full overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all ${strength.color}`}
                  style={{ width: `${Math.round((strength.score / 6) * 100)}%` }}
                />
              </div>
              <p className="text-xs text-gray-500 mt-1">
                Strength: <span className="font-medium">{strength.label}</span>
              </p>
            </div>
          )}
        </div>

        <div>
          <label htmlFor="confirm" className="block text-sm font-medium text-gray-700 mb-1">
            Confirm new password
          </label>
          <input
            id="confirm"
            type="password"
            autoComplete="new-password"
            required
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            className="input"
          />
        </div>

        <button type="submit" disabled={loading} className="btn-primary w-full">
          {loading ? "Updating…" : "Update password"}
        </button>
      </form>

      <p className="mt-4 text-center text-sm text-gray-500">
        <Link href="/login" className="text-brand-600 hover:text-brand-700">
          Back to sign in
        </Link>
      </p>
    </div>
  );
}

export default function ConfirmPage() {
  return (
    <Suspense fallback={<div className="card text-center text-sm text-gray-500">Loading…</div>}>
      <ConfirmForm />
    </Suspense>
  );
}
