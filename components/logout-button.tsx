"use client";

import { useRouter } from "next/navigation";
import { getCsrfToken } from "@/lib/client-utils";

export default function LogoutButton() {
  const router = useRouter();

  async function handleLogout() {
    await fetch("/api/auth/logout", {
      method: "POST",
      headers: { "x-csrf-token": getCsrfToken() },
    });
    router.push("/login");
    router.refresh();
  }

  return (
    <button onClick={handleLogout} className="btn-secondary text-sm">
      Sign out
    </button>
  );
}
