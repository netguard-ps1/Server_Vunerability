import React, { useEffect, useState } from 'react';
import { Shield } from 'lucide-react';
import MatrixBackground from './MatrixBackground';

const SplashScreen = ({ onComplete }) => {
  const [progress, setProgress] = useState(0);

  useEffect(() => {
    // Simulate loading progress
    const interval = setInterval(() => {
      setProgress((prev) => {
        if (prev >= 100) {
          clearInterval(interval);
          setTimeout(() => onComplete(), 500);
          return 100;
        }
        return prev + 10;
      });
    }, 150);

    return () => clearInterval(interval);
  }, [onComplete]);

  return (
    <div className="fixed inset-0 bg-cyber-dark z-50 flex items-center justify-center">
      <MatrixBackground />
      
      <div className="relative z-10 text-center">
        {/* Logo Animation */}
        <div className="mb-8 animate-float">
          <div className="relative inline-block">
            <div className="absolute inset-0 bg-cyber-blue/20 blur-3xl rounded-full"></div>
            <div className="relative p-6 bg-cyber-gray/50 backdrop-blur-md rounded-full border-2 border-cyber-blue">
              <Shield className="w-24 h-24 text-cyber-blue" />
            </div>
          </div>
        </div>

        {/* Title */}
        <h1 className="text-5xl font-bold text-white mb-2 tracking-tight">
          Server Vulnerability
        </h1>
        <p className="text-xl text-cyber-blue mb-8">
          Distributed Packet Capture System
        </p>

        {/* Loading Bar */}
        <div className="w-80 mx-auto">
          <div className="h-2 bg-cyber-gray rounded-full overflow-hidden border border-cyber-blue/30">
            <div
              className="h-full bg-gradient-to-r from-cyber-blue to-cyber-green transition-all duration-300 ease-out"
              style={{ width: `${progress}%` }}
            >
              <div className="h-full w-full bg-white/20 animate-pulse"></div>
            </div>
          </div>
          <p className="text-cyber-blue text-sm mt-3 font-mono">
            {progress < 100 ? 'Initializing system...' : 'Ready!'}
          </p>
        </div>

        {/* Version */}
        <p className="text-gray-500 text-xs mt-8">
          Version 1.0.0 | No Admin Required
        </p>
      </div>
    </div>
  );
};

export default SplashScreen;
