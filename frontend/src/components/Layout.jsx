import React from 'react';
import Sidebar from './Sidebar.jsx';

export default function Layout({ children, title, subtitle }) {
  return (
    <div className="flex h-screen bg-bg overflow-hidden">
      <Sidebar />
      <main className="flex-1 overflow-y-auto">
        <div className="max-w-5xl mx-auto px-6 py-6">
          {(title || subtitle) && (
            <div className="mb-6">
              {title && (
                <h1 className="text-xl font-bold text-slate-100">{title}</h1>
              )}
              {subtitle && (
                <p className="text-sm text-slate-500 mt-1">{subtitle}</p>
              )}
            </div>
          )}
          {children}
        </div>
      </main>
    </div>
  );
}
