"use client";

import { useState, useEffect, useCallback } from "react";
import { getCsrfToken } from "@/lib/client-utils";

type Entry = {
  id: string;
  amount: number;
  note: string;
  date: string;
};

export default function DashboardPage() {
  const [entries, setEntries] = useState<Entry[]>([]);
  const [savingsGoal, setSavingsGoal] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);

  const [amount, setAmount] = useState("");
  const [note, setNote] = useState("");
  const [date, setDate] = useState(new Date().toISOString().split("T")[0]);
  const [formError, setFormError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const fetchData = useCallback(async () => {
    const [entriesRes, goalRes] = await Promise.all([
      fetch("/api/entries"),
      fetch("/api/goal"),
    ]);
    const entriesData = await entriesRes.json();
    const goalData = await goalRes.json();

    if (entriesData.entries) setEntries(entriesData.entries);
    setSavingsGoal(goalData.savingsGoal ?? null);
    setLoading(false);
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const totalSaved = entries.reduce((sum, e) => sum + e.amount, 0);
  const goalPercent =
    savingsGoal && savingsGoal > 0
      ? Math.min(100, Math.round((totalSaved / savingsGoal) * 100))
      : null;

  async function handleAddEntry(e: React.FormEvent) {
    e.preventDefault();
    setFormError("");
    setSubmitting(true);

    try {
      const res = await fetch("/api/entries", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-csrf-token": getCsrfToken(),
        },
        body: JSON.stringify({ amount: parseFloat(amount), note, date }),
      });

      const data = await res.json();
      if (!res.ok) {
        setFormError(data.error ?? "Could not save entry.");
        return;
      }

      setAmount("");
      setNote("");
      setDate(new Date().toISOString().split("T")[0]);
      await fetchData();
    } catch {
      setFormError("Unable to connect. Please try again.");
    } finally {
      setSubmitting(false);
    }
  }

  async function handleDelete(id: string) {
    if (!confirm("Delete this entry?")) return;

    await fetch(`/api/entries/${id}`, {
      method: "DELETE",
      headers: { "x-csrf-token": getCsrfToken() },
    });

    setEntries((prev) => prev.filter((e) => e.id !== id));
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <p className="text-gray-500">Loading your savings…</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Stats row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div className="card">
          <p className="text-sm text-gray-500 mb-1">Total saved</p>
          <p className="text-3xl font-bold text-gray-900">
            ₦{totalSaved.toLocaleString("en-NG", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}
          </p>
          <p className="text-xs text-gray-400 mt-1">{entries.length} {entries.length === 1 ? "entry" : "entries"}</p>
        </div>

        {savingsGoal ? (
          <div className="card">
            <div className="flex items-center justify-between mb-2">
              <p className="text-sm text-gray-500">Goal progress</p>
              <span className="text-sm font-semibold text-brand-600">{goalPercent}%</span>
            </div>
            <div className="h-3 bg-gray-200 rounded-full overflow-hidden mb-2">
              <div
                className="h-full bg-brand-500 rounded-full transition-all duration-500"
                style={{ width: `${goalPercent}%` }}
              />
            </div>
            <p className="text-xs text-gray-400">
              ₦{totalSaved.toLocaleString()} of ₦{savingsGoal.toLocaleString()} goal
            </p>
          </div>
        ) : (
          <div className="card flex items-center justify-center text-center">
            <div>
              <p className="text-sm text-gray-500 mb-1">No savings goal set</p>
              <a href="/settings" className="text-sm text-brand-600 hover:text-brand-700 font-medium">
                Set a goal →
              </a>
            </div>
          </div>
        )}
      </div>

      {/* Add entry form */}
      <div className="card">
        <h2 className="text-base font-semibold text-gray-900 mb-4">Add a savings entry</h2>

        {formError && <p className="error-msg mb-4">{formError}</p>}

        <form onSubmit={handleAddEntry} className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div>
            <label htmlFor="amount" className="block text-sm font-medium text-gray-700 mb-1">
              Amount (₦)
            </label>
            <input
              id="amount"
              type="number"
              min="0.01"
              step="0.01"
              required
              value={amount}
              onChange={(e) => setAmount(e.target.value)}
              className="input"
              placeholder="0.00"
            />
          </div>
          <div>
            <label htmlFor="note" className="block text-sm font-medium text-gray-700 mb-1">
              Note
            </label>
            <input
              id="note"
              type="text"
              required
              maxLength={500}
              value={note}
              onChange={(e) => setNote(e.target.value)}
              className="input"
              placeholder="e.g. Monthly deposit"
            />
          </div>
          <div>
            <label htmlFor="date" className="block text-sm font-medium text-gray-700 mb-1">
              Date
            </label>
            <input
              id="date"
              type="date"
              required
              value={date}
              onChange={(e) => setDate(e.target.value)}
              className="input"
            />
          </div>
          <div className="sm:col-span-3">
            <button type="submit" disabled={submitting} className="btn-primary">
              {submitting ? "Saving…" : "Add entry"}
            </button>
          </div>
        </form>
      </div>

      {/* Entries list */}
      <div className="card">
        <h2 className="text-base font-semibold text-gray-900 mb-4">Savings history</h2>

        {entries.length === 0 ? (
          <p className="text-sm text-gray-500 text-center py-8">
            No entries yet. Add your first deposit above!
          </p>
        ) : (
          <div className="divide-y divide-gray-100">
            {entries.map((entry) => (
              <div
                key={entry.id}
                className="flex items-center justify-between py-3 group"
              >
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-gray-900 truncate">{entry.note}</p>
                  <p className="text-xs text-gray-400">
                    {new Date(entry.date).toLocaleDateString("en-NG", {
                      day: "numeric",
                      month: "short",
                      year: "numeric",
                    })}
                  </p>
                </div>
                <div className="flex items-center gap-3 ml-4">
                  <span className="text-sm font-semibold text-brand-700">
                    +₦{entry.amount.toLocaleString("en-NG", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}
                  </span>
                  <button
                    onClick={() => handleDelete(entry.id)}
                    className="text-gray-300 hover:text-red-500 transition-colors opacity-0 group-hover:opacity-100"
                    title="Delete entry"
                  >
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                    </svg>
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
