import React from 'react';
import { 
  Home, 
  Settings, 
  Bell, 
  Users, 
  Key, 
  Moon, 
  Sun,
  LogOut,
  UserPlus,
  Shield,
  HelpCircle
} from 'lucide-react';
import { useAppContext } from '../context/AppContext';

const Menu = () => {
  const { 
    isMenuOpen, 
    setIsMenuOpen, 
    theme, 
    toggleTheme, 
    notifications, 
    updateNotificationSetting 
  } = useAppContext();

  if (!isMenuOpen) return null;

  return (
    <div 
      className="fixed inset-0 bg-black bg-opacity-70 z-40" 
      onClick={() => setIsMenuOpen(false)}
    >
      <div 
        className="absolute top-0 left-0 w-80 h-full bg-gradient-to-b from-purple-900 via-purple-950 to-black border-r border-purple-700 shadow-2xl z-50 backdrop-blur-sm overflow-y-auto" 
        onClick={e => e.stopPropagation()}
      >
        <div className="p-4 border-b border-purple-800">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-xl font-bold bg-gradient-to-r from-purple-300 to-purple-500 bg-clip-text text-transparent">
              Menu
            </h2>
            <button 
              onClick={() => setIsMenuOpen(false)}
              className="p-2 hover:bg-purple-800 rounded-lg transition-colors"
            >
              <X className="h-5 w-5 text-purple-300" />
            </button>
          </div>
        </div>
        
        <div className="p-4 space-y-1">
          <button className="w-full flex items-center gap-3 p-3 hover:bg-purple-800 rounded-lg transition-colors text-left">
            <Home className="h-5 w-5 text-purple-300" />
            <span className="text-white">Home</span>
          </button>
          
          <button className="w-full flex items-center gap-3 p-3 hover:bg-purple-800 rounded-lg transition-colors text-left">
            <Users className="h-5 w-5 text-purple-300" />
            <span className="text-white">Contacts</span>
          </button>
          
          <button className="w-full flex items-center gap-3 p-3 hover:bg-purple-800 rounded-lg transition-colors text-left">
            <UserPlus className="h-5 w-5 text-purple-300" />
            <span className="text-white">Add Contact</span>
          </button>
          
          <div className="border-t border-purple-800 my-2"></div>
          
          <div className="p-3">
            <h3 className="text-purple-300 text-sm font-medium mb-2">Appearance</h3>
            <button 
              onClick={toggleTheme}
              className="w-full flex items-center justify-between p-2 hover:bg-purple-800 rounded-lg transition-colors"
            >
              <div className="flex items-center gap-2">
                {theme === 'dark' ? (
                  <Moon className="h-4 w-4 text-purple-300" />
                ) : (
                  <Sun className="h-4 w-4 text-yellow-400" />
                )}
                <span className="text-white">
                  {theme === 'dark' ? 'Dark Mode' : 'Light Mode'}
                </span>
              </div>
              <div className="text-purple-400 text-sm">
                {theme === 'dark' ? 'On' : 'Off'}
              </div>
            </button>
          </div>
          
          <div className="p-3">
            <h3 className="text-purple-300 text-sm font-medium mb-2">Notifications</h3>
            {Object.entries(notifications).map(([key, value]) => (
              <div key={key} className="flex items-center justify-between p-2">
                <span className="text-white capitalize">{key.replace(/([A-Z])/g, ' $1').trim()}</span>
                <label className="relative inline-flex items-center cursor-pointer">
                  <input 
                    type="checkbox" 
                    className="sr-only peer" 
                    checked={value}
                    onChange={() => updateNotificationSetting(key, !value)}
                  />
                  <div className="w-11 h-6 bg-gray-700 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-0.5 after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-purple-600"></div>
                </label>
              </div>
            ))}
          </div>
          
          <div className="border-t border-purple-800 my-2"></div>
          
          <button className="w-full flex items-center gap-3 p-3 hover:bg-purple-800 rounded-lg transition-colors text-left">
            <Shield className="h-5 w-5 text-purple-300" />
            <span className="text-white">Security & Privacy</span>
          </button>
          
          <button className="w-full flex items-center gap-3 p-3 hover:bg-purple-800 rounded-lg transition-colors text-left">
            <HelpCircle className="h-5 w-5 text-purple-300" />
            <span className="text-white">Help & Support</span>
          </button>
          
          <button className="w-full flex items-center gap-3 p-3 text-red-400 hover:bg-red-900 hover:bg-opacity-30 rounded-lg transition-colors mt-4">
            <LogOut className="h-5 w-5" />
            <span>Sign Out</span>
          </button>
        </div>
        
        <div className="p-4 border-t border-purple-800 mt-auto">
          <div className="text-center text-xs text-purple-500">
            <p>Scrambled Eggs v1.0.0</p>
            <p>Secure • Private • Decentralized</p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Menu;
