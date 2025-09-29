param(
    [Parameter(Mandatory=$true)]
    [string]$CommitMessage,
    
    [switch]$Push = $false
)

# Function to print colored messages
function Write-Color {
    param(
        [string]$Message,
        [string]$ForegroundColor = "White"
    )
    Write-Host $Message -ForegroundColor $ForegroundColor
}

# Check if there are changes to commit
$status = git status --porcelain
if (-not $status) {
    Write-Color "No changes to commit." -ForegroundColor "Yellow"
    exit 0
}

# Show git status
Write-Color "`n=== Git Status ===" -ForegroundColor "Cyan"
git status

# Add all changes
Write-Color "`n=== Staging changes... ===" -ForegroundColor "Cyan"
git add .

# Commit changes
Write-Color "`n=== Committing changes... ===" -ForegroundColor "Cyan"
git commit -m $CommitMessage

# Push changes if requested
if ($Push) {
    Write-Color "`n=== Pushing to remote... ===" -ForegroundColor "Cyan"
    git push origin main
}

Write-Color "`n=== Workflow completed! ===" -ForegroundColor "Green"
