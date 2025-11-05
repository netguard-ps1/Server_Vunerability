import React from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { Shield, Home, BarChart3, User, LogOut } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

const Navbar = ({ onDownloadClick }) => {
  const location = useLocation();
  const navigate = useNavigate();
  const { user, isAdmin, logout } = useAuth();

  const isActive = (path) => location.pathname === path;
  
  const handleLogout = () => {
    logout();
    navigate('/login');
    window.location.reload(); // Force reload to reset state
  };

  return (
    <nav className="fixed top-0 left-0 right-0 bg-cyber-gray/95 border-b border-cyber-blue/20 z-50 backdrop-blur-lg shadow-lg">
      <div className="w-full px-6 lg:px-12">
        <div className="flex items-center justify-between h-16">
          {/* Logo - Left Edge */}
          <Link to="/" className="flex items-center space-x-3 hover:opacity-80 transition-opacity">
            <Shield className="w-9 h-9 text-cyber-blue" />
            <div>
              <h1 className="text-xl font-bold text-white leading-tight">Server Vulnerability</h1>
              <p className="text-xs text-gray-400 leading-tight">Packet Capture System</p>
            </div>
          </Link>

          {/* Navigation Tabs and Auth - Right Side */}
          <div className="flex items-center space-x-3">
            {/* Navigation Tabs */}
            <div className="flex items-center space-x-2">
              <Link
                to="/"
                className={`flex items-center space-x-2 px-5 py-2 rounded-lg transition-all ${
                  isActive('/')
                    ? 'bg-cyber-blue text-cyber-dark font-semibold shadow-lg'
                    : 'text-gray-300 hover:bg-cyber-blue/10 hover:text-cyber-blue'
                }`}
              >
                <Home className="w-4 h-4" />
                <span className="font-medium">Dashboard</span>
              </Link>

              <Link
                to="/analysis"
                className={`flex items-center space-x-2 px-5 py-2 rounded-lg transition-all ${
                  isActive('/analysis')
                    ? 'bg-cyber-blue text-cyber-dark font-semibold shadow-lg'
                    : 'text-gray-300 hover:bg-cyber-blue/10 hover:text-cyber-blue'
                }`}
              >
                <BarChart3 className="w-4 h-4" />
                <span className="font-medium">Analysis</span>
              </Link>
            </div>

            {/* Divider */}
            <div className="h-8 w-px bg-cyber-blue/30"></div>

            {/* Auth Section */}
            <div className="flex items-center space-x-3">
            {user ? (
              <>
                <div className="flex items-center space-x-2 px-4 py-2 bg-cyber-dark/50 rounded-lg border border-cyber-blue/30">
                  <User className="w-4 h-4 text-cyber-blue" />
                  <span className="text-sm text-gray-300 font-medium">{user}</span>
                  {isAdmin && (
                    <span className="text-xs bg-cyber-blue text-cyber-dark px-2 py-1 rounded font-semibold">
                      ADMIN
                    </span>
                  )}
                </div>
                <button
                  onClick={handleLogout}
                  className="flex items-center space-x-2 px-4 py-2 bg-red-500/10 text-red-400 rounded-lg hover:bg-red-500/20 transition-all border border-red-500/30"
                  title="Logout"
                >
                  <LogOut className="w-4 h-4" />
                  <span className="font-medium">Logout</span>
                </button>
              </>
            ) : (
              <Link
                to="/login"
                className="flex items-center space-x-2 px-5 py-2 bg-cyber-blue text-cyber-dark rounded-lg hover:bg-cyber-blue/90 transition-all font-semibold shadow-lg"
              >
                <User className="w-4 h-4" />
                <span>Login</span>
              </Link>
            )}
            </div>
          </div>
        </div>
      </div>
    </nav>
  );
};

export default Navbar;
