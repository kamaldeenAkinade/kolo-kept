import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Kolo Kept",
  description: "Track your personal savings, one deposit at a time.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
