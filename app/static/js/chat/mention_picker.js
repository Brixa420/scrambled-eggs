class MentionPicker {
    constructor(inputElement, options = {}) {
        this.input = inputElement;
        this.options = {
            endpoint: '/api/conversations',
            onSelect: () => {},
            ...options
        };
        
        this.container = null;
        this.suggestions = [];
        this.selectedIndex = -1;
        this.conversationId = null;
        
        this.init();
    }
    
    init() {
        // Create the mention picker container
        this.container = document.createElement('div');
        this.container.className = 'mention-picker';
        this.container.style.display = 'none';
        document.body.appendChild(this.container);
        
        // Handle input events
        this.input.addEventListener('input', this.handleInput.bind(this));
        this.input.addEventListener('keydown', this.handleKeyDown.bind(this));
        
        // Handle clicks outside to close the picker
        document.addEventListener('click', (e) => {
            if (!this.container.contains(e.target) && e.target !== this.input) {
                this.hide();
            }
        });
    }
    
    async handleInput(e) {
        const cursorPosition = this.input.selectionStart;
        const textBeforeCursor = this.input.value.substring(0, cursorPosition);
        const lastAtPos = textBeforeCursor.lastIndexOf('@');
        
        // Check if we're in a mention
        if (lastAtPos !== -1 && (lastAtPos === 0 || /\s/.test(textBeforeCursor[lastAtPos - 1]))) {
            const query = textBeforeCursor.substring(lastAtPos + 1);
            
            if (!this.conversationId) {
                console.error('No conversation ID provided for mention picker');
                return;
            }
            
            try {
                const response = await fetch(`${this.options.endpoint}/${this.conversationId}/mentions/suggest?q=${encodeURIComponent(query)}`, {
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${localStorage.getItem('access_token')}`
                    }
                });
                
                if (response.ok) {
                    const data = await response.json();
                    this.suggestions = data;
                    this.showSuggestions(lastAtPos);
                }
            } catch (error) {
                console.error('Error fetching mention suggestions:', error);
            }
        } else {
            this.hide();
        }
    }
    
    showSuggestions(atPosition) {
        if (this.suggestions.length === 0) {
            this.hide();
            return;
        }
        
        this.container.innerHTML = '';
        this.selectedIndex = -1;
        
        // Position the picker
        const rect = this.input.getBoundingClientRect();
        this.container.style.position = 'absolute';
        this.container.style.top = `${rect.bottom + window.scrollY}px`;
        this.container.style.left = `${rect.left + (atPosition * 8)}px`; // Approximate character width
        this.container.style.display = 'block';
        
        // Add suggestions
        this.suggestions.forEach((user, index) => {
            const item = document.createElement('div');
            item.className = 'mention-item';
            item.innerHTML = `
                <img src="${user.avatar || '/static/images/default-avatar.png'}" alt="${user.username}" class="mention-avatar">
                <span class="mention-username">${user.username}</span>
            `;
            
            item.addEventListener('click', () => this.selectMention(user));
            this.container.appendChild(item);
        });
    }
    
    handleKeyDown(e) {
        if (!this.container || this.container.style.display === 'none') return;
        
        switch (e.key) {
            case 'ArrowDown':
                e.preventDefault();
                this.selectedIndex = Math.min(this.selectedIndex + 1, this.suggestions.length - 1);
                this.highlightSelected();
                break;
                
            case 'ArrowUp':
                e.preventDefault();
                this.selectedIndex = Math.max(this.selectedIndex - 1, -1);
                this.highlightSelected();
                break;
                
            case 'Enter':
                e.preventDefault();
                if (this.selectedIndex >= 0) {
                    this.selectMention(this.suggestions[this.selectedIndex]);
                }
                break;
                
            case 'Escape':
                e.preventDefault();
                this.hide();
                break;
        }
    }
    
    highlightSelected() {
        const items = this.container.querySelectorAll('.mention-item');
        items.forEach((item, index) => {
            item.classList.toggle('selected', index === this.selectedIndex);
        });
    }
    
    selectMention(user) {
        const cursorPosition = this.input.selectionStart;
        const textBeforeCursor = this.input.value.substring(0, cursorPosition);
        const lastAtPos = textBeforeCursor.lastIndexOf('@');
        
        if (lastAtPos !== -1) {
            const textAfterCursor = this.input.value.substring(cursorPosition);
            const newText = `${textBeforeCursor.substring(0, lastAtPos)}@${user.username} ${textAfterCursor}`;
            
            this.input.value = newText;
            
            // Move cursor to after the inserted mention
            const newCursorPos = lastAtPos + user.username.length + 2; // +2 for @ and space
            this.input.setSelectionRange(newCursorPos, newCursorPos);
            
            // Trigger input event to update any listeners
            this.input.dispatchEvent(new Event('input'));
            
            // Call the onSelect callback
            if (typeof this.options.onSelect === 'function') {
                this.options.onSelect(user);
            }
        }
        
        this.hide();
    }
    
    hide() {
        if (this.container) {
            this.container.style.display = 'none';
        }
    }
    
    setConversationId(conversationId) {
        this.conversationId = conversationId;
    }
}

// Export for ES modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = MentionPicker;
} else if (typeof window !== 'undefined') {
    window.MentionPicker = MentionPicker;
}
