#!/bin/bash
# =============================================================================
# Initialize public Git repository for Forensic Collector
# Run this script from the collector/ directory
# =============================================================================

set -e

echo "=== Forensic Collector: Public Repository Initialization ==="
echo ""

# Check we're in the right directory
if [ ! -f "src/main.py" ]; then
    echo "ERROR: Run this script from the collector/ directory"
    exit 1
fi

# Step 1: Initialize new git repo
echo "[1/5] Initializing new git repository..."
git init
git branch -M main

# Step 2: Verify .gitignore exclusions
echo ""
echo "[2/5] Verifying .gitignore exclusions..."

EXCLUDED_FILES=(
    "config.json"
    "config.production.json"
    "config.development.json"
    ".env"
    "dist/ForensicCollector.exe"
    "build/collector/ForensicCollector.pkg"
    "resources/winpmem_mini_x64.exe"
    "resources/libusb-1.0.dll"
    "resources/downgrade_apks/com.whatsapp.apk"
    "tools/libimobiledevice/idevicebackup2.exe"
)

ALLOWED_FILES=(
    ".env.example"
    "config.example.json"
    "resources/downgrade_apks/README.txt"
    "tools/libimobiledevice/.gitkeep"
    "README.md"
    "LICENSE"
    "SECURITY.md"
)

ALL_PASS=true
for f in "${EXCLUDED_FILES[@]}"; do
    if [ -f "$f" ] && ! git check-ignore -q "$f" 2>/dev/null; then
        echo "  WARNING: $f is NOT ignored"
        ALL_PASS=false
    else
        echo "  OK: $f (excluded)"
    fi
done

for f in "${ALLOWED_FILES[@]}"; do
    if [ -f "$f" ] && git check-ignore -q "$f" 2>/dev/null; then
        echo "  WARNING: $f is incorrectly ignored"
        ALL_PASS=false
    else
        echo "  OK: $f (included)"
    fi
done

if [ "$ALL_PASS" = false ]; then
    echo ""
    echo "WARNING: Some files may not be properly excluded. Review .gitignore."
    echo "Continue anyway? (y/N)"
    read -r answer
    [ "$answer" != "y" ] && exit 1
fi

# Step 3: Stage all files
echo ""
echo "[3/5] Staging files..."
git add .

# Step 4: Show what will be committed
echo ""
echo "[4/5] Files to be committed:"
git diff --cached --stat | tail -5
echo ""
echo "Total files staged: $(git diff --cached --name-only | wc -l)"

# Check for large files (>1MB)
echo ""
echo "Large files (>1MB) check:"
git diff --cached --name-only | while read f; do
    if [ -f "$f" ]; then
        size=$(stat -f%z "$f" 2>/dev/null || stat --printf="%s" "$f" 2>/dev/null || echo "0")
        if [ "$size" -gt 1048576 ] 2>/dev/null; then
            echo "  WARNING: $f ($(( size / 1024 ))KB)"
        fi
    fi
done

# Step 5: Initial commit
echo ""
echo "[5/5] Creating initial commit..."
git commit -m "Initial release: Forensic Artifact Collector v2.0.0

Cross-platform digital forensic artifact collection tool.
- Windows/macOS/Linux/Android/iOS artifact collection
- AES-256-GCM encrypted secure upload
- Chain of custody with SHA-256 integrity verification
- PyQt6 GUI with multi-language support

License: GPL-3.0"

echo ""
echo "=== Repository initialized successfully ==="
echo ""
echo "Next steps:"
echo "  1. Create a GitHub repository"
echo "  2. git remote add origin https://github.com/YOUR-ORG/forensic-collector.git"
echo "  3. git push -u origin main"
