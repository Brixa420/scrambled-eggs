# update-git.ps1
param(
    [string]$commitMessage = "Auto-update: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
    [switch]$push = $false,
    [string]$branch = "",
    [switch]$stash = $false,
    [switch]$pull = $false
)

# ===== Configuration =====
$REMOTE = "origin"
$MAIN_BRANCH = "main"
$CI_MODE = $env:CI -eq "true"

# ===== Functions =====
function Show-Header {
    if (-not $CI_MODE) {
        Clear-Host
        Write-Host "=== Git Automation Tool ===" -ForegroundColor Magenta
        Write-Host "==========================" -ForegroundColor Magenta
    }
}

function Invoke-GitCommand {
    param([string]$command, [string]$errorMessage = "Command failed")
    if ($CI_MODE) {
        $output = git @($command -split ' ') 2>&1
    } else {
        $output = git @($command -split ' ') 2>&1
    }
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: $errorMessage" -ForegroundColor Red
        Write-Host $output -ForegroundColor Red
        exit 1
    }
    return $output
}

# ===== Main Script =====
Show-Header

# Check if git is installed
try {
    $gitVersion = git --version
    Write-Host "SUCCESS: Git version: $gitVersion" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Git is not installed or not in PATH" -ForegroundColor Red
    exit 1
}

# Get current branch
$currentBranch = git rev-parse --abbrev-ref HEAD
if ([string]::IsNullOrEmpty($branch)) {
    $branch = $currentBranch
}

# Switch branch if needed
if ($branch -ne $currentBranch) {
    Write-Host "SWITCHING: Changing to branch: $branch" -ForegroundColor Cyan
    Invoke-GitCommand "checkout $branch" "Failed to switch to branch $branch"
}

# Stash changes if requested
$stashHash = $null
if ($stash) {
    Write-Host "STASHING: Saving current changes..." -ForegroundColor Cyan
    $stashOutput = git stash push -m "Auto-stash by update-git.ps1"
    if ($stashOutput -notlike "No local changes*") {
        $stashHash = ($stashOutput -split " ")[2]
        Write-Host "STASHED: Changes saved with hash: $stashHash" -ForegroundColor Cyan
    }
}

# Pull latest changes
if ($pull) {
    Write-Host "PULLING: Getting latest changes from $REMOTE/$branch..." -ForegroundColor Cyan
    Invoke-GitCommand "pull $REMOTE $branch" "Failed to pull from $REMOTE/$branch"
}

# Check for changes
$status = git status --porcelain
if (-not $status) {
    Write-Host "INFO: No changes to commit" -ForegroundColor Yellow
    
    # Pop stashed changes if any
    if ($stash -and $stashHash) {
        Write-Host "RESTORING: Bringing back stashed changes..." -ForegroundColor Cyan
        git stash pop
    }
    
    exit 0
}

# Show changes
Write-Host "CHANGES DETECTED:" -ForegroundColor Cyan
git status -s

# Add all changes
Write-Host "ADDING: Staging all changes..." -ForegroundColor Cyan
Invoke-GitCommand "add ." "Failed to stage changes"

# Commit changes
Write-Host "COMMITTING: Saving changes..." -ForegroundColor Cyan
Invoke-GitCommand "commit -m `"$commitMessage`"" "Failed to commit changes"

# Push changes if requested
if ($push) {
    Write-Host "PUSHING: Sending changes to $REMOTE/$branch..." -ForegroundColor Cyan
    Invoke-GitCommand "push $REMOTE $branch" "Failed to push to $REMOTE/$branch"
    Write-Host "SUCCESS: Changes pushed to $REMOTE/$branch" -ForegroundColor Green
} else {
    Write-Host "INFO: Use -push to send changes to remote" -ForegroundColor Yellow
}

# Pop stashed changes if any
if ($stash -and $stashHash) {
    Write-Host "RESTORING: Bringing back stashed changes..." -ForegroundColor Cyan
    git stash pop
}

# CI/CD Integration
if ($CI_MODE) {
    Write-Host "CI: Git operations completed successfully" -ForegroundColor Green
}

Write-Host "SUCCESS: Update complete!" -ForegroundColor Green
