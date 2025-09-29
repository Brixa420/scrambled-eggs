# Save this as update-github.ps1 in your project root

param(
    [string] = "Auto-update: 2025-09-28 23:52:07"
)

# Function to display colored messages
function Write-Status {
    param(,  = "White")
    Write-Host "
[23:52:07] " -NoNewline
    Write-Host  -ForegroundColor 
}

try {
    # 1. Navigate to project root
     = Split-Path -Parent 
    Set-Location 
    Write-Status "Working in directory: " "Cyan"

    # 2. Check for changes
     = git status --porcelain
    if (-not ) {
        Write-Status "No changes to commit." "Green"
        exit 0
    }

    # 3. Add all changes
    Write-Status "Staging changes..." "Yellow"
    git add .

    # 4. Commit changes
    Write-Status "Committing changes with message: " "Yellow"
    git commit -m 

    # 5. Get current branch
     = git branch --show-current
    if (-not ) {
         = "main"
    }

    # 6. Push changes
    Write-Status "Pushing to ..." "Yellow"
    git push origin 

    Write-Status "Successfully updated GitHub repository!" "Green"
}
catch {
    Write-Status "Error: " "Red"
    exit 1
}
