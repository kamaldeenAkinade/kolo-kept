export default function AuthLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="min-h-screen bg-gradient-to-br from-brand-50 to-white flex items-center justify-center px-4 py-12">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-brand-600 text-white text-2xl font-bold mb-4 shadow-lg">
            K
          </div>
          <h1 className="text-2xl font-bold text-gray-900">Kolo Kept</h1>
          <p className="text-sm text-gray-500 mt-1">Your personal savings tracker</p>
        </div>
        {children}
      </div>
    </div>
  );
}
