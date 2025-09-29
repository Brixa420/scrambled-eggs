param(
    [Parameter(Mandatory=$true)]
    [string]$Message
)

# Add all changes
git add .

# Commit with message
git commit -m $Message

# Push to main branch
git push origin main

# Show status
git status
