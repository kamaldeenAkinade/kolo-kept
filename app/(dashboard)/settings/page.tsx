"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { getCsrfToken } from "@/lib/client-utils";
import { getPasswordStrengthLabel } from "@/lib/password";

export default function SettingsPage() {
  const router = useRouter();

  // Goal state
  const [savingsGoal, setSavingsGoal] = useState("");
  const [goalLoading, setGoalLoading] = useState(true);
  const [goalMsg, setGoalMsg] = useState<{ type: "ok" | "err"; text: string } | null>(null);
  const [goalSubmitting, setGoalSubmitting] = useState(false);

  // Password change state
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [pwMsg, setPwMsg] = useState<{ type: "ok" | "err"; text: string } | null>(null);
  const [pwSubmitting, setPwSubmitting] = useState(false);

  // Logout everywhere state
  const [logoutLoading, setLogoutLoading] = useState(false);

  const newPwStrength = newPassword ? getPasswordStrengthLabel(newPassword) : null;

  useEffect(() => {
    fetch("/api/goal").then((r) => r.json()).then((d) => {
      if (d.savingsGoal) setSavingsGoal(String(d.savingsGoal));
      setGoalLoading(false);
    });
  }, []);

  async function handleGoalSave(e: React.FormEvent) {
    e.preventDefault();
    setGoalMsg(null);
    setGoalSubmitting(true);

    try {
      const res = await fetch("/api/goal", {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          "x-csrf-token": getCsrfToken(),
        },
        body: JSON.stringify({
          savingsGoal: savingsGoal ? parseFloat(savingsGoal) : null,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        setGoalMsg({ type: "err", text: data.error ?? "Failed to update goal." });
      } else {
        setGoalMsg({ type: "ok", text: "Goal updated successfully." });
      }
    } catch {
      setGoalMsg({ type: "err", text: "Unable to connect." });
    } finally {
      setGoalSubmitting(false);
    }
  }

  async function handlePasswordChange(e: React.FormEvent) {
    e.preventDefault();
    setPwMsg(null);

    if (newPassword !== confirmPassword) {
      setPwMsg({ type: "err", text: "New passwords do not match." });
      return;
    }

    setPwSubmitting(true);
    try {
      const res = await fetch("/api/auth/change-password", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-csrf-token": getCsrfToken(),
        },
        body: JSON.stringify({ currentPassword, newPassword }),
      });

      const data = await res.json();
      if (!res.ok) {
        setPwMsg({ type: "err", text: data.error ?? "Failed to change password." });
      } else {
        setPwMsg({ type: "ok", text: "Password changed successfully." });
        setCurrentPassword("");
        setNewPassword("");
        setConfirmPassword("");
      }
    } catch {
      setPwMsg({ type: "err", text: "Unable to connect." });
    } finally {
      setPwSubmitting(false);
    }
  }

  async function handleLogoutEverywhere() {
    if (
      !confirm(
        "This will sign you out of all devices, including this one. Continue?"
      )
    )
      return;

    setLogoutLoading(true);
    try {
      await fetch("/api/auth/logout-everywhere", {
        method: "POST",
        headers: { "x-csrf-token": getCsrfToken() },
      });
      router.push("/login");
      router.refresh();
    } catch {
      setLogoutLoading(false);
    }
  }

  return (
    <div className="space-y-6 max-w-2xl">
      <h1 className="text-2xl font-bold text-gray-900">Settings</h1>

      {/* Savings Goal */}
      <div className="card">
        <h2 className="text-base font-semibold text-gray-900 mb-4">Savings goal</h2>

        {goalMsg && (
          <p className={`mb-4 ${goalMsg.type === "ok" ? "success-msg" : "error-msg"}`}>
            {goalMsg.text}
          </p>
        )}

        <form onSubmit={handleGoalSave} className="flex gap-3 items-end">
          <div className="flex-1">
            <label htmlFor="goal" className="block text-sm font-medium text-gray-700 mb-1">
              Target amount (₦)
            </label>
            <input
              id="goal"
              type="number"
              min="1"
              step="1"
              value={savingsGoal}
              onChange={(e) => setSavingsGoal(e.target.value)}
              disabled={goalLoading}
              className="input"
              placeholder="e.g. 500000"
            />
          </div>
          <button
            type="submit"
            disabled={goalSubmitting || goalLoading}
            className="btn-primary"
          >
            {goalSubmitting ? "Saving…" : "Save goal"}
          </button>
        </form>
      </div>

      {/* Change Password */}
      <div className="card">
        <h2 className="text-base font-semibold text-gray-900 mb-4">Change password</h2>

        {pwMsg && (
          <p className={`mb-4 ${pwMsg.type === "ok" ? "success-msg" : "error-msg"}`}>
            {pwMsg.text}
          </p>
        )}

        <form onSubmit={handlePasswordChange} className="space-y-4">
          <div>
            <label htmlFor="currentPw" className="block text-sm font-medium text-gray-700 mb-1">
              Current password
            </label>
            <input
              id="currentPw"
              type="password"
              autoComplete="current-password"
              required
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              className="input"
            />
          </div>
          <div>
            <label htmlFor="newPw" className="block text-sm font-medium text-gray-700 mb-1">
              New password
            </label>
            <input
              id="newPw"
              type="password"
              autoComplete="new-password"
              required
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              className="input"
              placeholder="At least 12 characters"
            />
            {newPassword && newPwStrength && (
              <div className="mt-1.5">
                <div className="h-1.5 bg-gray-200 rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all ${newPwStrength.color}`}
                    style={{ width: `${Math.round((newPwStrength.score / 6) * 100)}%` }}
                  />
                </div>
                <p className="text-xs text-gray-500 mt-1">Strength: {newPwStrength.label}</p>
              </div>
            )}
          </div>
          <div>
            <label htmlFor="confirmPw" className="block text-sm font-medium text-gray-700 mb-1">
              Confirm new password
            </label>
            <input
              id="confirmPw"
              type="password"
              autoComplete="new-password"
              required
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              className="input"
            />
          </div>
          <button type="submit" disabled={pwSubmitting} className="btn-primary">
            {pwSubmitting ? "Updating…" : "Update password"}
          </button>
        </form>
      </div>

      {/* Log out everywhere */}
      <div className="card border border-red-100">
        <h2 className="text-base font-semibold text-gray-900 mb-2">Session management</h2>
        <p className="text-sm text-gray-600 mb-4">
          Sign out of all devices and browsers where your account is currently active.
          This invalidates every active session immediately.
        </p>
        <button
          onClick={handleLogoutEverywhere}
          disabled={logoutLoading}
          className="btn-danger"
        >
          {logoutLoading ? "Signing out…" : "Log out everywhere"}
        </button>
      </div>
    </div>
  );
}
