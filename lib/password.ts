export type PasswordValidationResult =
  | { valid: true }
  | { valid: false; message: string };

export function validatePasswordStrength(
  password: string
): PasswordValidationResult {
  if (password.length < 12) {
    return {
      valid: false,
      message: "Password must be at least 12 characters long.",
    };
  }
  if (!/[A-Z]/.test(password)) {
    return {
      valid: false,
      message: "Password must contain at least one uppercase letter.",
    };
  }
  if (!/[a-z]/.test(password)) {
    return {
      valid: false,
      message: "Password must contain at least one lowercase letter.",
    };
  }
  if (!/[0-9]/.test(password)) {
    return {
      valid: false,
      message: "Password must contain at least one number.",
    };
  }
  if (!/[^A-Za-z0-9]/.test(password)) {
    return {
      valid: false,
      message: "Password must contain at least one special character.",
    };
  }
  return { valid: true };
}

export function getPasswordStrengthLabel(password: string): {
  score: number;
  label: string;
  color: string;
} {
  let score = 0;
  if (password.length >= 12) score++;
  if (password.length >= 16) score++;
  if (/[A-Z]/.test(password)) score++;
  if (/[a-z]/.test(password)) score++;
  if (/[0-9]/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;

  if (score <= 2) return { score, label: "Weak", color: "bg-red-500" };
  if (score <= 4) return { score, label: "Fair", color: "bg-yellow-500" };
  if (score === 5) return { score, label: "Good", color: "bg-blue-500" };
  return { score, label: "Strong", color: "bg-brand-500" };
}
