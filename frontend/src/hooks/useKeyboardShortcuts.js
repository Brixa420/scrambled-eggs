import { useCallback, useEffect } from 'react';

const useKeyboardShortcuts = (shortcuts) => {
  const handleKeyDown = useCallback((event) => {
    // Skip if typing in an input or textarea
    if (
      event.target.tagName === 'INPUT' || 
      event.target.tagName === 'TEXTAREA' ||
      event.target.isContentEditable
    ) {
      return;
    }

    // Create a string representation of the key combination
    const key = [
      event.ctrlKey && 'Control',
      event.metaKey && 'Meta',
      event.altKey && 'Alt',
      event.shiftKey && 'Shift',
      !['Control', 'Meta', 'Alt', 'Shift'].includes(event.key) && event.key,
    ]
      .filter(Boolean)
      .join('+');

    // Find and execute the matching shortcut
    const shortcut = shortcuts.find(s => s.key === key);
    if (shortcut) {
      event.preventDefault();
      shortcut.action();
    }
  }, [shortcuts]);

  useEffect(() => {
    window.addEventListener('keydown', handleKeyDown);
    return () => {
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, [handleKeyDown]);

  return null;
};

export default useKeyboardShortcuts;
