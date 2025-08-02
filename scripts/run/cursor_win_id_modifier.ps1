# Set output encoding to UTF-8
$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Color definitions
$RED = "`e[31m"
$GREEN = "`e[32m"
$YELLOW = "`e[33m"
$BLUE = "`e[34m"
$NC = "`e[0m"

# Configuration file path
$STORAGE_FILE = "$env:APPDATA\Cursor\User\globalStorage\storage.json"
$BACKUP_DIR = "$env:APPDATA\Cursor\User\globalStorage\backups"

# Native PowerShell method to generate a random string
function Generate-RandomString {
    param([int]$Length)
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    $result = ""
    for ($i = 0; $i -lt $Length; $i++) {
        $result += $chars[(Get-Random -Maximum $chars.Length)]
    }
    return $result
}

# Modify Cursor core JS files to bypass device identification (ported from macOS version)
function Modify-CursorJSFiles {
    Write-Host ""
    Write-Host "$BLUE🔧 [Core Modification]$NC Starting to modify Cursor core JS files to bypass device identification..."
    Write-Host ""

    # Cursor app path for Windows
    $cursorAppPath = "${env:LOCALAPPDATA}\Programs\Cursor"
    if (-not (Test-Path $cursorAppPath)) {
        # Try other possible installation paths
        $alternatePaths = @(
            "${env:ProgramFiles}\Cursor",
            "${env:ProgramFiles(x86)}\Cursor",
            "${env:USERPROFILE}\AppData\Local\Programs\Cursor"
        )

        foreach ($path in $alternatePaths) {
            if (Test-Path $path) {
                $cursorAppPath = $path
                break
            }
        }

        if (-not (Test-Path $cursorAppPath)) {
            Write-Host "$RED❌ [Error]$NC Cursor application installation path not found"
            Write-Host "$YELLOW💡 [Hint]$NC Please confirm that Cursor is installed correctly"
            return $false
        }
    }

    Write-Host "$GREEN✅ [Found]$NC Found Cursor installation path: $cursorAppPath"

    # Generate new device identifiers
    $newUuid = [System.Guid]::NewGuid().ToString().ToLower()
    $machineId = "auth0|user_$(Generate-RandomString -Length 32)"
    $deviceId = [System.Guid]::NewGuid().ToString().ToLower()
    $macMachineId = Generate-RandomString -Length 64

    Write-Host "$GREEN🔑 [Generated]$NC New device identifiers have been generated"

    # Target JS file list (Windows paths)
    $jsFiles = @(
        "$cursorAppPath\resources\app\out\vs\workbench\api\node\extensionHostProcess.js",
        "$cursorAppPath\resources\app\out\main.js",
        "$cursorAppPath\resources\app\out\vs\code\node\cliProcessMain.js"
    )

    $modifiedCount = 0
    $needModification = $false

    # Check if modification is needed
    Write-Host "$BLUE🔍 [Checking]$NC Checking JS file modification status..."
    foreach ($file in $jsFiles) {
        if (-not (Test-Path $file)) {
            Write-Host "$YELLOW⚠️  [Warning]$NC File does not exist: $(Split-Path $file -Leaf)"
            continue
        }

        $content = Get-Content $file -Raw -ErrorAction SilentlyContinue
        if ($content -and $content -notmatch "return crypto\.randomUUID\(\)") {
            Write-Host "$BLUE📝 [Needed]$NC File needs modification: $(Split-Path $file -Leaf)"
            $needModification = $true
            break
        } else {
            Write-Host "$GREEN✅ [Modified]$NC File already modified: $(Split-Path $file -Leaf)"
        }
    }

    if (-not $needModification) {
        Write-Host "$GREEN✅ [Skipped]$NC All JS files have already been modified, no need to repeat the operation"
        return $true
    }

    # Close Cursor processes
    Write-Host "$BLUE🔄 [Closing]$NC Closing Cursor processes for file modification..."
    Stop-AllCursorProcesses -MaxRetries 3 -WaitSeconds 3 | Out-Null

    # Create backup
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $backupPath = "$env:TEMP\Cursor_JS_Backup_$timestamp"

    Write-Host "$BLUE💾 [Backup]$NC Creating Cursor JS file backup..."
    try {
        New-Item -ItemType Directory -Path $backupPath -Force | Out-Null
        foreach ($file in $jsFiles) {
            if (Test-Path $file) {
                $fileName = Split-Path $file -Leaf
                Copy-Item $file "$backupPath\$fileName" -Force
            }
        }
        Write-Host "$GREEN✅ [Backup]$NC Backup created successfully: $backupPath"
    } catch {
        Write-Host "$RED❌ [Error]$NC Failed to create backup: $($_.Exception.Message)"
        return $false
    }

    # Modify JS files
    Write-Host "$BLUE🔧 [Modifying]$NC Starting to modify JS files..."

    foreach ($file in $jsFiles) {
        if (-not (Test-Path $file)) {
            Write-Host "$YELLOW⚠️  [Skipped]$NC File does not exist: $(Split-Path $file -Leaf)"
            continue
        }

        Write-Host "$BLUE📝 [Processing]$NC Processing: $(Split-Path $file -Leaf)"

        try {
            $content = Get-Content $file -Raw -Encoding UTF8

            # Check if already modified
            if ($content -match "return crypto\.randomUUID\(\)" -or $content -match "// Cursor ID Modifier Tool Injection") {
                Write-Host "$GREEN✅ [Skipped]$NC File has already been modified"
                $modifiedCount++
                continue
            }

            # ES module compatible JavaScript injection code
            $timestampVar = [DateTimeOffset]::Now.ToUnixTimeSeconds()
            $injectCode = @"
// Cursor ID Modifier Tool Injection - $(Get-Date) - ES Module Compatible Version
import crypto from 'crypto';

// Save original function reference
const originalRandomUUID_${timestampVar} = crypto.randomUUID;

// Override crypto.randomUUID method
crypto.randomUUID = function() {
    return '${newUuid}';
};

// Override all possible system ID acquisition functions - ES Module Compatible Version
globalThis.getMachineId = function() { return '${machineId}'; };
globalThis.getDeviceId = function() { return '${deviceId}'; };
globalThis.macMachineId = '${macMachineId}';

// Ensure accessibility in different environments
if (typeof window !== 'undefined') {
    window.getMachineId = globalThis.getMachineId;
    window.getDeviceId = globalThis.getDeviceId;
    window.macMachineId = globalThis.macMachineId;
}

// Ensure execution at the top level of the module
console.log('Cursor device identifier successfully hijacked - ES Module Version by JianbingGuozi(86) Follow the public account [JianbingGuoziJuanAI] to discuss more Cursor tips and AI knowledge (script is free, follow the public account to join the group for more tips and experts)');

"@

            # Method 1: Find IOPlatformUUID related functions
            if ($content -match "IOPlatformUUID") {
                Write-Host "$BLUE🔍 [Found]$NC Found IOPlatformUUID keyword"

                # Modify for different function patterns
                if ($content -match "function a\$") {
                    $content = $content -replace "function a\$\(t\)\{switch", "function a`$(t){return crypto.randomUUID(); switch"
                    Write-Host "$GREEN✅ [Success]$NC Modified a`$ function successfully"
                    $modifiedCount++
                    continue
                }

                # Generic injection method
                $content = $injectCode + $content
                Write-Host "$GREEN✅ [Success]$NC Generic injection method modification successful"
                $modifiedCount++
            }
            # Method 2: Find other device ID related functions
            elseif ($content -match "function t\$\(\)" -or $content -match "async function y5") {
                Write-Host "$BLUE🔍 [Found]$NC Found device ID related functions"

                # Modify MAC address acquisition function
                if ($content -match "function t\$\(\)") {
                    $content = $content -replace "function t\$\(\)\{", "function t`$(){return `"00:00:00:00:00:00`";"
                    Write-Host "$GREEN✅ [Success]$NC Modified MAC address acquisition function"
                }

                # Modify device ID acquisition function
                if ($content -match "async function y5") {
                    $content = $content -replace "async function y5\(t\)\{", "async function y5(t){return crypto.randomUUID();"
                    Write-Host "$GREEN✅ [Success]$NC Modified device ID acquisition function"
                }

                $modifiedCount++
            }
            else {
                Write-Host "$YELLOW⚠️  [Warning]$NC No known device ID function pattern found, using generic injection"
                $content = $injectCode + $content
                $modifiedCount++
            }

            # Write the modified content
            Set-Content -Path $file -Value $content -Encoding UTF8 -NoNewline
            Write-Host "$GREEN✅ [Done]$NC File modification complete: $(Split-Path $file -Leaf)"

        } catch {
            Write-Host "$RED❌ [Error]$NC Failed to modify file: $($_.Exception.Message)"
            # Try to restore from backup
            $fileName = Split-Path $file -Leaf
            $backupFile = "$backupPath\$fileName"
            if (Test-Path $backupFile) {
                Copy-Item $backupFile $file -Force
                Write-Host "$YELLOW🔄 [Restored]$NC Restored file from backup"
            }
        }
    }

    if ($modifiedCount -gt 0) {
        Write-Host ""
        Write-Host "$GREEN🎉 [Complete]$NC Successfully modified $modifiedCount JS files"
        Write-Host "$BLUE💾 [Backup]$NC Original files backed up to: $backupPath"
        Write-Host "$BLUE💡 [Note]$NC JavaScript injection feature enabled to bypass device identification"
        return $true
    } else {
        Write-Host "$RED❌ [Failed]$NC Failed to modify any files"
        return $false
    }
}


# 🚀 New feature: Delete folders to prevent Cursor Pro trial from expiring
function Remove-CursorTrialFolders {
    Write-Host ""
    Write-Host "$GREEN🎯 [Core Feature]$NC Executing Cursor Pro trial anti-expiration folder deletion..."
    Write-Host "$BLUE📋 [Note]$NC This feature will delete specified Cursor-related folders to reset the trial status"
    Write-Host ""

    # Define folder paths to be deleted
    $foldersToDelete = @()

    # Windows Administrator user paths
    $adminPaths = @(
        "C:\Users\Administrator\.cursor",
        "C:\Users\Administrator\AppData\Roaming\Cursor"
    )

    # Current user paths
    $currentUserPaths = @(
        "$env:USERPROFILE\.cursor",
        "$env:APPDATA\Cursor"
    )

    # Merge all paths
    $foldersToDelete += $adminPaths
    $foldersToDelete += $currentUserPaths

    Write-Host "$BLUE📂 [Detecting]$NC The following folders will be checked:"
    foreach ($folder in $foldersToDelete) {
        Write-Host "    📁 $folder"
    }
    Write-Host ""

    $deletedCount = 0
    $skippedCount = 0
    $errorCount = 0

    # Delete specified folders
    foreach ($folder in $foldersToDelete) {
        Write-Host "$BLUE🔍 [Checking]$NC Checking folder: $folder"

        if (Test-Path $folder) {
            try {
                Write-Host "$YELLOW⚠️  [Warning]$NC Folder found, deleting..."
                Remove-Item -Path $folder -Recurse -Force -ErrorAction Stop
                Write-Host "$GREEN✅ [Success]$NC Deleted folder: $folder"
                $deletedCount++
            }
            catch {
                Write-Host "$RED❌ [Error]$NC Failed to delete folder: $folder"
                Write-Host "$RED💥 [Details]$NC Error message: $($_.Exception.Message)"
                $errorCount++
            }
        } else {
            Write-Host "$YELLOW⏭️  [Skipped]$NC Folder does not exist: $folder"
            $skippedCount++
        }
        Write-Host ""
    }

    # Display operation statistics
    Write-Host "$GREEN📊 [Statistics]$NC Operation complete statistics:"
    Write-Host "    ✅ Successfully deleted: $deletedCount folders"
    Write-Host "    ⏭️  Skipped: $skippedCount folders"
    Write-Host "    ❌ Deletion failed: $errorCount folders"
    Write-Host ""

    if ($deletedCount -gt 0) {
        Write-Host "$GREEN🎉 [Complete]$NC Cursor Pro trial anti-expiration folder deletion complete!"

        # 🔧 Pre-create necessary directory structure to avoid permission issues
        Write-Host "$BLUE🔧 [Fixing]$NC Pre-creating necessary directory structure to avoid permission issues..."

        $cursorAppData = "$env:APPDATA\Cursor"
        $cursorLocalAppData = "$env:LOCALAPPDATA\cursor"
        $cursorUserProfile = "$env:USERPROFILE\.cursor"

        # Create main directories
        try {
            if (-not (Test-Path $cursorAppData)) {
                New-Item -ItemType Directory -Path $cursorAppData -Force | Out-Null
            }
            if (-not (Test-Path $cursorUserProfile)) {
                New-Item -ItemType Directory -Path $cursorUserProfile -Force | Out-Null
            }
            Write-Host "$GREEN✅ [Complete]$NC Directory structure pre-creation complete"
        } catch {
            Write-Host "$YELLOW⚠️  [Warning]$NC Problem occurred during directory pre-creation: $($_.Exception.Message)"
        }
    } else {
        Write-Host "$YELLOW🤔 [Hint]$NC No folders to delete were found, they may have already been cleaned up"
    }
    Write-Host ""
}

# 🔄 Restart Cursor and wait for configuration file generation
function Restart-CursorAndWait {
    Write-Host ""
    Write-Host "$GREEN🔄 [Restarting]$NC Restarting Cursor to regenerate configuration file..."

    if (-not $global:CursorProcessInfo) {
        Write-Host "$RED❌ [Error]$NC Cursor process information not found, cannot restart"
        return $false
    }

    $cursorPath = $global:CursorProcessInfo.Path

    # Fix: ensure path is a string type
    if ($cursorPath -is [array]) {
        $cursorPath = $cursorPath[0]
    }

    # Verify path is not empty
    if ([string]::IsNullOrEmpty($cursorPath)) {
        Write-Host "$RED❌ [Error]$NC Cursor path is empty"
        return $false
    }

    Write-Host "$BLUE📍 [Path]$NC Using path: $cursorPath"

    if (-not (Test-Path $cursorPath)) {
        Write-Host "$RED❌ [Error]$NC Cursor executable does not exist: $cursorPath"

        # Try using alternative paths
        $backupPaths = @(
            "$env:LOCALAPPDATA\Programs\cursor\Cursor.exe",
            "$env:PROGRAMFILES\Cursor\Cursor.exe",
            "$env:PROGRAMFILES(X86)\Cursor\Cursor.exe"
        )

        $foundPath = $null
        foreach ($backupPath in $backupPaths) {
            if (Test-Path $backupPath) {
                $foundPath = $backupPath
                Write-Host "$GREEN💡 [Found]$NC Using alternative path: $foundPath"
                break
            }
        }

        if (-not $foundPath) {
            Write-Host "$RED❌ [Error]$NC Cannot find a valid Cursor executable"
            return $false
        }

        $cursorPath = $foundPath
    }

    try {
        Write-Host "$GREEN🚀 [Starting]$NC Starting Cursor..."
        $process = Start-Process -FilePath $cursorPath -PassThru -WindowStyle Hidden

        Write-Host "$YELLOW⏳ [Waiting]$NC Waiting 20 seconds for Cursor to fully start and generate configuration file..."
        Start-Sleep -Seconds 20

        # Check if configuration file is generated
        $configPath = "$env:APPDATA\Cursor\User\globalStorage\storage.json"
        $maxWait = 45
        $waited = 0

        while (-not (Test-Path $configPath) -and $waited -lt $maxWait) {
            Write-Host "$YELLOW⏳ [Waiting]$NC Waiting for configuration file to be generated... ($waited/$maxWait seconds)"
            Start-Sleep -Seconds 1
            $waited++
        }

        if (Test-Path $configPath) {
            Write-Host "$GREEN✅ [Success]$NC Configuration file generated: $configPath"

            # Extra wait to ensure file is fully written
            Write-Host "$YELLOW⏳ [Waiting]$NC Waiting 5 seconds to ensure configuration file is fully written..."
            Start-Sleep -Seconds 5
        } else {
            Write-Host "$YELLOW⚠️  [Warning]$NC Configuration file was not generated within the expected time"
            Write-Host "$BLUE💡 [Hint]$NC You may need to start Cursor manually once to generate the configuration file"
        }

        # Force close Cursor
        Write-Host "$YELLOW🔄 [Closing]$NC Closing Cursor for configuration modification..."
        if ($process -and -not $process.HasExited) {
            $process.Kill()
            $process.WaitForExit(5000)
        }

        # Ensure all Cursor processes are closed
        Get-Process -Name "Cursor" -ErrorAction SilentlyContinue | Stop-Process -Force
        Get-Process -Name "cursor" -ErrorAction SilentlyContinue | Stop-Process -Force

        Write-Host "$GREEN✅ [Complete]$NC Cursor restart process complete"
        return $true

    } catch {
        Write-Host "$RED❌ [Error]$NC Failed to restart Cursor: $($_.Exception.Message)"
        Write-Host "$BLUE💡 [Debug]$NC Error details: $($_.Exception.GetType().FullName)"
        return $false
    }
}

# 🔒 Force close all Cursor processes (enhanced version)
function Stop-AllCursorProcesses {
    param(
        [int]$MaxRetries = 3,
        [int]$WaitSeconds = 5
    )

    Write-Host "$BLUE🔒 [Process Check]$NC Checking and closing all Cursor-related processes..."

    # Define all possible Cursor process names
    $cursorProcessNames = @(
        "Cursor",
        "cursor",
        "Cursor Helper",
        "Cursor Helper (GPU)",
        "Cursor Helper (Plugin)",
        "Cursor Helper (Renderer)",
        "CursorUpdater"
    )

    for ($retry = 1; $retry -le $MaxRetries; $retry++) {
        Write-Host "$BLUE🔍 [Checking]$NC Process check attempt $retry/$MaxRetries..."

        $foundProcesses = @()
        foreach ($processName in $cursorProcessNames) {
            $processes = Get-Process -Name $processName -ErrorAction SilentlyContinue
            if ($processes) {
                $foundProcesses += $processes
                Write-Host "$YELLOW⚠️  [Found]$NC Process: $processName (PID: $($processes.Id -join ', '))"
            }
        }

        if ($foundProcesses.Count -eq 0) {
            Write-Host "$GREEN✅ [Success]$NC All Cursor processes are closed"
            return $true
        }

        Write-Host "$YELLOW🔄 [Closing]$NC Closing $($foundProcesses.Count) Cursor processes..."

        # First try to close gracefully
        foreach ($process in $foundProcesses) {
            try {
                $process.CloseMainWindow() | Out-Null
                Write-Host "$BLUE  • Graceful close: $($process.ProcessName) (PID: $($process.Id))$NC"
            } catch {
                Write-Host "$YELLOW  • Graceful close failed: $($process.ProcessName)$NC"
            }
        }

        Start-Sleep -Seconds 3

        # Force terminate still running processes
        foreach ($processName in $cursorProcessNames) {
            $processes = Get-Process -Name $processName -ErrorAction SilentlyContinue
            if ($processes) {
                foreach ($process in $processes) {
                    try {
                        Stop-Process -Id $process.Id -Force
                        Write-Host "$RED  • Force terminate: $($process.ProcessName) (PID: $($process.Id))$NC"
                    } catch {
                        Write-Host "$RED  • Force terminate failed: $($process.ProcessName)$NC"
                    }
                }
            }
        }

        if ($retry -lt $MaxRetries) {
            Write-Host "$YELLOW⏳ [Waiting]$NC Waiting $WaitSeconds seconds before re-checking..."
            Start-Sleep -Seconds $WaitSeconds
        }
    }

    Write-Host "$RED❌ [Failed]$NC Cursor processes are still running after $MaxRetries attempts"
    return $false
}

# 🔐 Check file permissions and lock status
function Test-FileAccessibility {
    param(
        [string]$FilePath
    )

    Write-Host "$BLUE🔐 [Permission Check]$NC Checking file access permissions: $(Split-Path $FilePath -Leaf)"

    if (-not (Test-Path $FilePath)) {
        Write-Host "$RED❌ [Error]$NC File does not exist"
        return $false
    }

    # Check if the file is locked
    try {
        $fileStream = [System.IO.File]::Open($FilePath, 'Open', 'ReadWrite', 'None')
        $fileStream.Close()
        Write-Host "$GREEN✅ [Permissions]$NC File is readable/writable, not locked"
        return $true
    } catch [System.IO.IOException] {
        Write-Host "$RED❌ [Locked]$NC File is locked by another process: $($_.Exception.Message)"
        return $false
    } catch [System.UnauthorizedAccessException] {
        Write-Host "$YELLOW⚠️  [Permissions]$NC File permissions are restricted, trying to modify permissions..."

        # Try to modify file permissions
        try {
            $file = Get-Item $FilePath
            if ($file.IsReadOnly) {
                $file.IsReadOnly = $false
                Write-Host "$GREEN✅ [Fixed]$NC Removed read-only attribute"
            }

            # Test again
            $fileStream = [System.IO.File]::Open($FilePath, 'Open', 'ReadWrite', 'None')
            $fileStream.Close()
            Write-Host "$GREEN✅ [Permissions]$NC Permission fix successful"
            return $true
        } catch {
            Write-Host "$RED❌ [Permissions]$NC Failed to fix permissions: $($_.Exception.Message)"
            return $false
        }
    } catch {
        Write-Host "$RED❌ [Error]$NC Unknown error: $($_.Exception.Message)"
        return $false
    }
}

# 🧹 Cursor initialization cleanup function (ported from old version)
function Invoke-CursorInitialization {
    Write-Host ""
    Write-Host "$GREEN🧹 [Initializing]$NC Performing Cursor initialization cleanup..."
    $BASE_PATH = "$env:APPDATA\Cursor\User"

    $filesToDelete = @(
        (Join-Path -Path $BASE_PATH -ChildPath "globalStorage\state.vscdb"),
        (Join-Path -Path $BASE_PATH -ChildPath "globalStorage\state.vscdb.backup")
    )

    $folderToCleanContents = Join-Path -Path $BASE_PATH -ChildPath "History"
    $folderToDeleteCompletely = Join-Path -Path $BASE_PATH -ChildPath "workspaceStorage"

    Write-Host "$BLUE🔍 [Debug]$NC Base path: $BASE_PATH"

    # Delete specified files
    foreach ($file in $filesToDelete) {
        Write-Host "$BLUE🔍 [Checking]$NC Checking file: $file"
        if (Test-Path $file) {
            try {
                Remove-Item -Path $file -Force -ErrorAction Stop
                Write-Host "$GREEN✅ [Success]$NC Deleted file: $file"
            }
            catch {
                Write-Host "$RED❌ [Error]$NC Failed to delete file $file: $($_.Exception.Message)"
            }
        } else {
            Write-Host "$YELLOW⚠️  [Skipped]$NC File does not exist, skipping deletion: $file"
        }
    }

    # Clean contents of specified folder
    Write-Host "$BLUE🔍 [Checking]$NC Checking folder to clean: $folderToCleanContents"
    if (Test-Path $folderToCleanContents) {
        try {
            Get-ChildItem -Path $folderToCleanContents -Recurse | Remove-Item -Force -Recurse -ErrorAction Stop
            Write-Host "$GREEN✅ [Success]$NC Cleaned folder contents: $folderToCleanContents"
        }
        catch {
            Write-Host "$RED❌ [Error]$NC Failed to clean folder $folderToCleanContents: $($_.Exception.Message)"
        }
    } else {
        Write-Host "$YELLOW⚠️  [Skipped]$NC Folder does not exist, skipping cleaning: $folderToCleanContents"
    }

    # Completely delete specified folder
    Write-Host "$BLUE🔍 [Checking]$NC Checking folder to delete: $folderToDeleteCompletely"
    if (Test-Path $folderToDeleteCompletely) {
        try {
            Remove-Item -Path $folderToDeleteCompletely -Recurse -Force -ErrorAction Stop
            Write-Host "$GREEN✅ [Success]$NC Deleted folder: $folderToDeleteCompletely"
        }
        catch {
            Write-Host "$RED❌ [Error]$NC Failed to delete folder $folderToDeleteCompletely: $($_.Exception.Message)"
        }
    } else {
        Write-Host "$YELLOW⚠️  [Skipped]$NC Folder does not exist, skipping deletion: $folderToDeleteCompletely"
    }

    Write-Host "$GREEN✅ [Complete]$NC Cursor initialization cleanup complete"
    Write-Host ""
}

# 🔧 Modify system registry MachineGuid (ported from old version)
function Update-MachineGuid {
    try {
        Write-Host "$BLUE🔧 [Registry]$NC Modifying system registry MachineGuid..."

        # Check if registry path exists, create if not
        $registryPath = "HKLM:\SOFTWARE\Microsoft\Cryptography"
        if (-not (Test-Path $registryPath)) {
            Write-Host "$YELLOW⚠️  [Warning]$NC Registry path does not exist: $registryPath, creating..."
            New-Item -Path $registryPath -Force | Out-Null
            Write-Host "$GREEN✅ [Info]$NC Registry path created successfully"
        }

        # Get the current MachineGuid, use empty string as default if it doesn't exist
        $originalGuid = ""
        try {
            $currentGuid = Get-ItemProperty -Path $registryPath -Name MachineGuid -ErrorAction SilentlyContinue
            if ($currentGuid) {
                $originalGuid = $currentGuid.MachineGuid
                Write-Host "$GREEN✅ [Info]$NC Current registry value:"
                Write-Host "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography"
                Write-Host "    MachineGuid    REG_SZ    $originalGuid"
            } else {
                Write-Host "$YELLOW⚠️  [Warning]$NC MachineGuid value does not exist, will create a new one"
            }
        } catch {
            Write-Host "$YELLOW⚠️  [Warning]$NC Failed to read registry: $($_.Exception.Message)"
            Write-Host "$YELLOW⚠️  [Warning]$NC Will attempt to create a new MachineGuid value"
        }

        # Create backup file (only if original value exists)
        $backupFile = $null
        if ($originalGuid) {
            $backupFile = "$BACKUP_DIR\MachineGuid_$(Get-Date -Format 'yyyyMMdd_HHmmss').reg"
            Write-Host "$BLUE💾 [Backup]$NC Backing up registry..."
            $backupResult = Start-Process "reg.exe" -ArgumentList "export", "`"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography`"", "`"$backupFile`"" -NoNewWindow -Wait -PassThru

            if ($backupResult.ExitCode -eq 0) {
                Write-Host "$GREEN✅ [Backup]$NC Registry key backed up to: $backupFile"
            } else {
                Write-Host "$YELLOW⚠️  [Warning]$NC Backup creation failed, continuing..."
                $backupFile = $null
            }
        }

        # Generate new GUID
        $newGuid = [System.Guid]::NewGuid().ToString()
        Write-Host "$BLUE🔄 [Generating]$NC New MachineGuid: $newGuid"

        # Update or create registry value
        Set-ItemProperty -Path $registryPath -Name MachineGuid -Value $newGuid -Force -ErrorAction Stop

        # Verify update
        $verifyGuid = (Get-ItemProperty -Path $registryPath -Name MachineGuid -ErrorAction Stop).MachineGuid
        if ($verifyGuid -ne $newGuid) {
            throw "Registry verification failed: updated value ($verifyGuid) does not match expected value ($newGuid)"
        }

        Write-Host "$GREEN✅ [Success]$NC Registry update successful:"
        Write-Host "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography"
        Write-Host "    MachineGuid    REG_SZ    $newGuid"
        return $true
    }
    catch {
        Write-Host "$RED❌ [Error]$NC Registry operation failed: $($_.Exception.Message)"

        # Try to restore backup (if it exists)
        if ($backupFile -and (Test-Path $backupFile)) {
            Write-Host "$YELLOW🔄 [Restoring]$NC Restoring from backup..."
            $restoreResult = Start-Process "reg.exe" -ArgumentList "import", "`"$backupFile`"" -NoNewWindow -Wait -PassThru

            if ($restoreResult.ExitCode -eq 0) {
                Write-Host "$GREEN✅ [Restore Successful]$NC Restored original registry value"
            } else {
                Write-Host "$RED❌ [Error]$NC Restore failed, please import backup file manually: $backupFile"
            }
        } else {
            Write-Host "$YELLOW⚠️  [Warning]$NC Backup file not found or backup creation failed, cannot restore automatically"
        }

        return $false
    }
}

# Check configuration file and environment
function Test-CursorEnvironment {
    param(
        [string]$Mode = "FULL"
    )

    Write-Host ""
    Write-Host "$BLUE🔍 [Environment Check]$NC Checking Cursor environment..."

    $configPath = "$env:APPDATA\Cursor\User\globalStorage\storage.json"
    $cursorAppData = "$env:APPDATA\Cursor"
    $issues = @()

    # Check configuration file
    if (-not (Test-Path $configPath)) {
        $issues += "Configuration file does not exist: $configPath"
    } else {
        try {
            $content = Get-Content $configPath -Raw -Encoding UTF8 -ErrorAction Stop
            $config = $content | ConvertFrom-Json -ErrorAction Stop
            Write-Host "$GREEN✅ [Check]$NC Configuration file format is correct"
        } catch {
            $issues += "Configuration file format error: $($_.Exception.Message)"
        }
    }

    # Check Cursor directory structure
    if (-not (Test-Path $cursorAppData)) {
        $issues += "Cursor application data directory does not exist: $cursorAppData"
    }

    # Check Cursor installation
    $cursorPaths = @(
        "$env:LOCALAPPDATA\Programs\cursor\Cursor.exe",
        "$env:PROGRAMFILES\Cursor\Cursor.exe",
        "$env:PROGRAMFILES(X86)\Cursor\Cursor.exe"
    )

    $cursorFound = $false
    foreach ($path in $cursorPaths) {
        if (Test-Path $path) {
            Write-Host "$GREEN✅ [Check]$NC Found Cursor installation: $path"
            $cursorFound = $true
            break
        }
    }

    if (-not $cursorFound) {
        $issues += "Cursor installation not found, please confirm Cursor is installed correctly"
    }

    # Return check results
    if ($issues.Count -eq 0) {
        Write-Host "$GREEN✅ [Environment Check]$NC All checks passed"
        return @{ Success = $true; Issues = @() }
    } else {
        Write-Host "$RED❌ [Environment Check]$NC Found $($issues.Count) issues:"
        foreach ($issue in $issues) {
            Write-Host "$RED  • ${issue}$NC"
        }
        return @{ Success = $false; Issues = $issues }
    }
}

# 🛠️ Modify machine code configuration (enhanced version)
function Modify-MachineCodeConfig {
    param(
        [string]$Mode = "FULL"
    )

    Write-Host ""
    Write-Host "$GREEN🛠️  [Configuration]$NC Modifying machine code configuration..."

    $configPath = "$env:APPDATA\Cursor\User\globalStorage\storage.json"

    # Enhanced configuration file check
    if (-not (Test-Path $configPath)) {
        Write-Host "$RED❌ [Error]$NC Configuration file does not exist: $configPath"
        Write-Host ""
        Write-Host "$YELLOW💡 [Solution]$NC Please try the following steps:"
        Write-Host "$BLUE  1️⃣  Manually start the Cursor application$NC"
        Write-Host "$BLUE  2️⃣  Wait for Cursor to fully load (about 30 seconds)$NC"
        Write-Host "$BLUE  3️⃣  Close the Cursor application$NC"
        Write-Host "$BLUE  4️⃣  Rerun this script$NC"
        Write-Host ""
        Write-Host "$YELLOW⚠️  [Alternative]$NC If the problem persists:"
        Write-Host "$BLUE  • Choose the 'Reset Environment + Modify Machine Code' option in the script$NC"
        Write-Host "$BLUE  • This option will automatically generate the configuration file$NC"
        Write-Host ""

        # Provide user choice
        $userChoice = Read-Host "Try starting Cursor now to generate the configuration file? (y/n)"
        if ($userChoice -match "^(y|yes)$") {
            Write-Host "$BLUE🚀 [Attempting]$NC Attempting to start Cursor..."
            return Start-CursorToGenerateConfig
        }

        return $false
    }

    # Ensure processes are fully closed even in machine code only modification mode
    if ($Mode -eq "MODIFY_ONLY") {
        Write-Host "$BLUE🔒 [Security Check]$NC Even in modify-only mode, it's necessary to ensure Cursor processes are fully closed"
        if (-not (Stop-AllCursorProcesses -MaxRetries 3 -WaitSeconds 3)) {
            Write-Host "$RED❌ [Error]$NC Failed to close all Cursor processes, modification may fail"
            $userChoice = Read-Host "Force continue? (y/n)"
            if ($userChoice -notmatch "^(y|yes)$") {
                return $false
            }
        }
    }

    # Check file permissions and lock status
    if (-not (Test-FileAccessibility -FilePath $configPath)) {
        Write-Host "$RED❌ [Error]$NC Cannot access configuration file, it may be locked or have insufficient permissions"
        return $false
    }

    # Verify configuration file format and display structure
    try {
        Write-Host "$BLUE🔍 [Verifying]$NC Checking configuration file format..."
        $originalContent = Get-Content $configPath -Raw -Encoding UTF8 -ErrorAction Stop
        $config = $originalContent | ConvertFrom-Json -ErrorAction Stop
        Write-Host "$GREEN✅ [Verified]$NC Configuration file format is correct"

        # Display relevant properties in the current configuration file
        Write-Host "$BLUE📋 [Current Config]$NC Checking existing telemetry properties:"
        $telemetryProperties = @('telemetry.machineId', 'telemetry.macMachineId', 'telemetry.devDeviceId', 'telemetry.sqmId')
        foreach ($prop in $telemetryProperties) {
            if ($config.PSObject.Properties[$prop]) {
                $value = $config.$prop
                $displayValue = if ($value.Length -gt 20) { "$($value.Substring(0,20))..." } else { $value }
                Write-Host "$GREEN  ✓ ${prop}$NC = $displayValue"
            } else {
                Write-Host "$YELLOW  - ${prop}$NC (does not exist, will be created)"
            }
        }
        Write-Host ""
    } catch {
        Write-Host "$RED❌ [Error]$NC Configuration file format error: $($_.Exception.Message)"
        Write-Host "$YELLOW💡 [Suggestion]$NC The configuration file may be corrupted, it's recommended to choose the 'Reset Environment + Modify Machine Code' option"
        return $false
    }

    # Implement atomic file operations and retry mechanism
    $maxRetries = 3
    $retryCount = 0

    while ($retryCount -lt $maxRetries) {
        $retryCount++
        Write-Host ""
        Write-Host "$BLUE🔄 [Attempting]$NC Modification attempt $retryCount/$maxRetries..."

        try {
            # Display operation progress
            Write-Host "$BLUE⏳ [Progress]$NC 1/6 - Generating new device identifiers..."

            # Generate new IDs
            $MAC_MACHINE_ID = [System.Guid]::NewGuid().ToString()
            $UUID = [System.Guid]::NewGuid().ToString()
            $prefixBytes = [System.Text.Encoding]::UTF8.GetBytes("auth0|user_")
            $prefixHex = -join ($prefixBytes | ForEach-Object { '{0:x2}' -f $_ })
            $randomBytes = New-Object byte[] 32
            $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
            $rng.GetBytes($randomBytes)
            $randomPart = [System.BitConverter]::ToString($randomBytes) -replace '-',''
            $rng.Dispose()
            $MACHINE_ID = "${prefixHex}${randomPart}"
            $SQM_ID = "{$([System.Guid]::NewGuid().ToString().ToUpper())}"

            Write-Host "$GREEN✅ [Progress]$NC 1/6 - Device identifier generation complete"

            Write-Host "$BLUE⏳ [Progress]$NC 2/6 - Creating backup directory..."

            # Backup original values (enhanced version)
            $backupDir = "$env:APPDATA\Cursor\User\globalStorage\backups"
            if (-not (Test-Path $backupDir)) {
                New-Item -ItemType Directory -Path $backupDir -Force -ErrorAction Stop | Out-Null
            }

            $backupName = "storage.json.backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')_retry$retryCount"
            $backupPath = "$backupDir\$backupName"

            Write-Host "$BLUE⏳ [Progress]$NC 3/6 - Backing up original configuration..."
            Copy-Item $configPath $backupPath -ErrorAction Stop

            # Verify backup was successful
            if (Test-Path $backupPath) {
                $backupSize = (Get-Item $backupPath).Length
                $originalSize = (Get-Item $configPath).Length
                if ($backupSize -eq $originalSize) {
                    Write-Host "$GREEN✅ [Progress]$NC 3/6 - Configuration backup successful: $backupName"
                } else {
                    Write-Host "$YELLOW⚠️  [Warning]$NC Backup file size does not match, but continuing"
                }
            } else {
                throw "Backup file creation failed"
            }

            Write-Host "$BLUE⏳ [Progress]$NC 4/6 - Reading original configuration into memory..."

            # Atomic operation: read original content into memory
            $originalContent = Get-Content $configPath -Raw -Encoding UTF8 -ErrorAction Stop
            $config = $originalContent | ConvertFrom-Json -ErrorAction Stop

            Write-Host "$BLUE⏳ [Progress]$NC 5/6 - Updating configuration in memory..."

            # Update configuration values (safe way, ensure properties exist)
            $propertiesToUpdate = @{
                'telemetry.machineId' = $MACHINE_ID
                'telemetry.macMachineId' = $MAC_MACHINE_ID
                'telemetry.devDeviceId' = $UUID
                'telemetry.sqmId' = $SQM_ID
            }

            foreach ($property in $propertiesToUpdate.GetEnumerator()) {
                $key = $property.Key
                $value = $property.Value

                # Safe way using Add-Member or direct assignment
                if ($config.PSObject.Properties[$key]) {
                    # Property exists, update directly
                    $config.$key = $value
                    Write-Host "$BLUE  ✓ Updating property: ${key}$NC"
                } else {
                    # Property does not exist, add new property
                    $config | Add-Member -MemberType NoteProperty -Name $key -Value $value -Force
                    Write-Host "$BLUE  + Adding property: ${key}$NC"
                }
            }

            Write-Host "$BLUE⏳ [Progress]$NC 6/6 - Atomically writing new configuration file..."

            # Atomic operation: delete original file, write new file
            $tempPath = "$configPath.tmp"
            $updatedJson = $config | ConvertTo-Json -Depth 10

            # Write to temporary file
            [System.IO.File]::WriteAllText($tempPath, $updatedJson, [System.Text.Encoding]::UTF8)

            # Verify temporary file
            $tempContent = Get-Content $tempPath -Raw -Encoding UTF8
            $tempConfig = $tempContent | ConvertFrom-Json

            # Verify all properties were written correctly
            $tempVerificationPassed = $true
            foreach ($property in $propertiesToUpdate.GetEnumerator()) {
                $key = $property.Key
                $expectedValue = $property.Value
                $actualValue = $tempConfig.$key

                if ($actualValue -ne $expectedValue) {
                    $tempVerificationPassed = $false
                    Write-Host "$RED  ✗ Temporary file verification failed: ${key}$NC"
                    break
                }
            }

            if (-not $tempVerificationPassed) {
                Remove-Item $tempPath -Force -ErrorAction SilentlyContinue
                throw "Temporary file verification failed"
            }

            # Atomic replacement: delete original file, rename temporary file
            Remove-Item $configPath -Force
            Move-Item $tempPath $configPath

            # Set file to read-only (optional)
            $file = Get-Item $configPath
            $file.IsReadOnly = $false  # Keep writable for subsequent modifications

            # Final verification of modification results
            Write-Host "$BLUE🔍 [Final Verification]$NC Verifying new configuration file..."

            $verifyContent = Get-Content $configPath -Raw -Encoding UTF8
            $verifyConfig = $verifyContent | ConvertFrom-Json

            $verificationPassed = $true
            $verificationResults = @()

            # Safely verify each property
            foreach ($property in $propertiesToUpdate.GetEnumerator()) {
                $key = $property.Key
                $expectedValue = $property.Value
                $actualValue = $verifyConfig.$key

                if ($actualValue -eq $expectedValue) {
                    $verificationResults += "✓ ${key}: Verification passed"
                } else {
                    $verificationResults += "✗ ${key}: Verification failed (Expected: ${expectedValue}, Actual: ${actualValue})"
                    $verificationPassed = $false
                }
            }

            # Display verification results
            Write-Host "$BLUE📋 [Verification Details]$NC"
            foreach ($result in $verificationResults) {
                Write-Host "    $result"
            }

            if ($verificationPassed) {
                Write-Host "$GREEN✅ [Success]$NC Modification successful on attempt $retryCount!"
                Write-Host ""
                Write-Host "$GREEN🎉 [Complete]$NC Machine code configuration modification complete!"
                Write-Host "$BLUE📋 [Details]$NC The following identifiers have been updated:"
                Write-Host "    🔹 machineId: $MACHINE_ID"
                Write-Host "    🔹 macMachineId: $MAC_MACHINE_ID"
                Write-Host "    🔹 devDeviceId: $UUID"
                Write-Host "    🔹 sqmId: $SQM_ID"
                Write-Host ""
                Write-Host "$GREEN💾 [Backup]$NC Original configuration backed up to: $backupName"

                # 🔒 Add configuration file protection mechanism
                Write-Host "$BLUE🔒 [Protection]$NC Setting configuration file protection..."
                try {
                    $configFile = Get-Item $configPath
                    $configFile.IsReadOnly = $true
                    Write-Host "$GREEN✅ [Protection]$NC Configuration file set to read-only to prevent Cursor from overwriting modifications"
                    Write-Host "$BLUE💡 [Hint]$NC File path: $configPath"
                } catch {
                    Write-Host "$YELLOW⚠️  [Protection]$NC Failed to set read-only attribute: $($_.Exception.Message)"
                    Write-Host "$BLUE💡 [Suggestion]$NC You can manually right-click the file → Properties → check 'Read-only'"
                }
                Write-Host "$BLUE 🔒 [Security]$NC It's recommended to restart Cursor to ensure the configuration takes effect"
                return $true
            } else {
                Write-Host "$RED❌ [Failed]$NC Verification failed on attempt $retryCount"
                if ($retryCount -lt $maxRetries) {
                    Write-Host "$BLUE🔄 [Restoring]$NC Restoring backup, preparing to retry..."
                    Copy-Item $backupPath $configPath -Force
                    Start-Sleep -Seconds 2
                    continue  # Continue to next retry
                } else {
                    Write-Host "$RED❌ [Final Failure]$NC All retries failed, restoring original configuration"
                    Copy-Item $backupPath $configPath -Force
                    return $false
                }
            }

        } catch {
            Write-Host "$RED❌ [Exception]$NC Exception occurred on attempt $retryCount: $($_.Exception.Message)"
            Write-Host "$BLUE💡 [Debug Info]$NC Error type: $($_.Exception.GetType().FullName)"

            # Clean up temporary file
            if (Test-Path "$configPath.tmp") {
                Remove-Item "$configPath.tmp" -Force -ErrorAction SilentlyContinue
            }

            if ($retryCount -lt $maxRetries) {
                Write-Host "$BLUE🔄 [Restoring]$NC Restoring backup, preparing to retry..."
                if (Test-Path $backupPath) {
                    Copy-Item $backupPath $configPath -Force
                }
                Start-Sleep -Seconds 3
                continue  # Continue to next retry
            } else {
                Write-Host "$RED❌ [Final Failure]$NC All retries failed"
                # Try to restore backup
                if (Test-Path $backupPath) {
                    Write-Host "$BLUE🔄 [Restoring]$NC Restoring backup configuration..."
                    try {
                        Copy-Item $backupPath $configPath -Force
                        Write-Host "$GREEN✅ [Restored]$NC Restored original configuration"
                    } catch {
                        Write-Host "$RED❌ [Error]$NC Failed to restore backup: $($_.Exception.Message)"
                    }
                }
                return $false
            }
        }
    }

    # If we get here, all retries have failed
    Write-Host "$RED❌ [Final Failure]$NC Failed to complete modification after $maxRetries attempts"
    return $false

}

#  Start Cursor to generate configuration file
function Start-CursorToGenerateConfig {
    Write-Host "$BLUE🚀 [Starting]$NC Attempting to start Cursor to generate configuration file..."

    # Find Cursor executable
    $cursorPaths = @(
        "$env:LOCALAPPDATA\Programs\cursor\Cursor.exe",
        "$env:PROGRAMFILES\Cursor\Cursor.exe",
        "$env:PROGRAMFILES(X86)\Cursor\Cursor.exe"
    )

    $cursorPath = $null
    foreach ($path in $cursorPaths) {
        if (Test-Path $path) {
            $cursorPath = $path
            break
        }
    }

    if (-not $cursorPath) {
        Write-Host "$RED❌ [Error]$NC Cursor installation not found, please confirm Cursor is installed correctly"
        return $false
    }

    try {
        Write-Host "$BLUE📍 [Path]$NC Using Cursor path: $cursorPath"

        # Start Cursor
        $process = Start-Process -FilePath $cursorPath -PassThru -WindowStyle Normal
        Write-Host "$GREEN🚀 [Started]$NC Cursor started, PID: $($process.Id)"

        Write-Host "$YELLOW⏳ [Waiting]$NC Please wait for Cursor to fully load (about 30 seconds)..."
        Write-Host "$BLUE💡 [Hint]$NC You can manually close Cursor after it has fully loaded"

        # Wait for configuration file to be generated
        $configPath = "$env:APPDATA\Cursor\User\globalStorage\storage.json"
        $maxWait = 60
        $waited = 0

        while (-not (Test-Path $configPath) -and $waited -lt $maxWait) {
            Start-Sleep -Seconds 2
            $waited += 2
            if ($waited % 10 -eq 0) {
                Write-Host "$YELLOW⏳ [Waiting]$NC Waiting for configuration file to be generated... ($waited/$maxWait seconds)"
            }
        }

        if (Test-Path $configPath) {
            Write-Host "$GREEN✅ [Success]$NC Configuration file generated!"
            Write-Host "$BLUE💡 [Hint]$NC You can now close Cursor and rerun the script"
            return $true
        } else {
            Write-Host "$YELLOW⚠️  [Timeout]$NC Configuration file was not generated within the expected time"
            Write-Host "$BLUE💡 [Suggestion]$NC Please perform an action in Cursor (like creating a new file) to trigger configuration generation"
            return $false
        }

    } catch {
        Write-Host "$RED❌ [Error]$NC Failed to start Cursor: $($_.Exception.Message)"
        return $false
    }
}

# Check for administrator privileges
function Test-Administrator {
    $user = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($user)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Administrator)) {
    Write-Host "$RED[Error]$NC Please run this script as an administrator"
    Write-Host "Please right-click the script and select 'Run as administrator'"
    Read-Host "Press Enter to exit"
    exit 1
}

# Display Logo
Clear-Host
Write-Host @"

    ██████╗██╗    ██╗██████╗ ███████╗ ██████╗ ██████╗ 
    ██╔════╝██║    ██║██╔══██╗██╔════╝██╔═══██╗██╔══██╗
    ██║     ██║    ██║██████╔╝███████╗██║   ██║██████╔╝
    ██║     ██║    ██║██╔══██╗╚════██║██║   ██║██╔══██╗
    ╚██████╗╚██████╔╝██║  ██║███████║╚██████╔╝██║  ██║
     ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝

"@
Write-Host "$BLUE================================$NC"
Write-Host "$GREEN🚀   Cursor Pro Trial Anti-Expiration Tool       $NC"
Write-Host "$YELLOW📱  Follow the public account [JianbingGuoziJuanAI] $NC"
Write-Host "$YELLOW🤝  Let's discuss more Cursor tips and AI knowledge together (script is free, follow the public account to join the group for more tips and experts)  $NC"
Write-Host "$YELLOW💡  [Important Note] This tool is free. If it helps you, please follow the public account [JianbingGuoziJuanAI]  $NC"
Write-Host ""
Write-Host "$YELLOW💰   [Small Ad] Selling CursorPro educational accounts with a one-year warranty for three months, find me if you need one (86), WeChat: JavaRookie666  $NC"
Write-Host "$BLUE================================$NC"

# 🎯 User selection menu
Write-Host ""
Write-Host "$GREEN🎯 [Select Mode]$NC Please select the operation you want to perform:"
Write-Host ""
Write-Host "$BLUE  1️⃣  Modify Machine Code Only$NC"
Write-Host "$YELLOW      • Executes the machine code modification function$NC"
Write-Host "$YELLOW      • Injects cracked JS code into core files$NC"
Write-Host "$YELLOW      • Skips folder deletion/environment reset steps$NC"
Write-Host "$YELLOW      • Preserves existing Cursor configuration and data$NC"
Write-Host ""
Write-Host "$BLUE  2️⃣  Reset Environment + Modify Machine Code$NC"
Write-Host "$RED      • Performs a full environment reset (deletes Cursor folders)$NC"
Write-Host "$RED      • ⚠️  Configuration will be lost, please back up if needed$NC"
Write-Host "$YELLOW      • Modifies the machine code$NC"
Write-Host "$YELLOW      • Injects cracked JS code into core files$NC"
Write-Host "$YELLOW      • This is equivalent to the current full script behavior$NC"
Write-Host ""

# Get user choice
do {
    $userChoice = Read-Host "Please enter your choice (1 or 2)"
    if ($userChoice -eq "1") {
        Write-Host "$GREEN✅ [Selected]$NC You chose: Modify Machine Code Only"
        $executeMode = "MODIFY_ONLY"
        break
    } elseif ($userChoice -eq "2") {
        Write-Host "$GREEN✅ [Selected]$NC You chose: Reset Environment + Modify Machine Code"
        Write-Host "$RED⚠️  [Important Warning]$NC This operation will delete all Cursor configuration files!"
        $confirmReset = Read-Host "Confirm full reset? (enter yes to confirm, any other key to cancel)"
        if ($confirmReset -eq "yes") {
            $executeMode = "RESET_AND_MODIFY"
            break
        } else {
            Write-Host "$YELLOW👋 [Canceled]$NC User canceled the reset operation"
            continue
        }
    } else {
        Write-Host "$RED❌ [Error]$NC Invalid choice, please enter 1 or 2"
    }
} while ($true)

Write-Host ""

# 📋 Display execution flow based on selection
if ($executeMode -eq "MODIFY_ONLY") {
    Write-Host "$GREEN📋 [Execution Flow]$NC Modify Machine Code Only mode will execute the following steps:"
    Write-Host "$BLUE  1️⃣  Detect Cursor configuration file$NC"
    Write-Host "$BLUE  2️⃣  Back up existing configuration file$NC"
    Write-Host "$BLUE  3️⃣  Modify machine code configuration$NC"
    Write-Host "$BLUE  4️⃣  Display operation completion message$NC"
    Write-Host ""
    Write-Host "$YELLOW⚠️  [Notes]$NC"
    Write-Host "$YELLOW  • Will not delete any folders or reset the environment$NC"
    Write-Host "$YELLOW  • Preserves all existing configurations and data$NC"
    Write-Host "$YELLOW  • The original configuration file will be backed up automatically$NC"
} else {
    Write-Host "$GREEN📋 [Execution Flow]$NC Reset Environment + Modify Machine Code mode will execute the following steps:"
    Write-Host "$BLUE  1️⃣  Detect and close Cursor processes$NC"
    Write-Host "$BLUE  2️⃣  Save Cursor program path information$NC"
    Write-Host "$BLUE  3️⃣  Delete specified Cursor trial-related folders$NC"
    Write-Host "$BLUE      📁 C:\Users\Administrator\.cursor$NC"
    Write-Host "$BLUE      📁 C:\Users\Administrator\AppData\Roaming\Cursor$NC"
    Write-Host "$BLUE      📁 C:\Users\%USERNAME%\.cursor$NC"
    Write-Host "$BLUE      📁 C:\Users\%USERNAME%\AppData\Roaming\Cursor$NC"
    Write-Host "$BLUE  3.5️⃣ Pre-create necessary directory structure to avoid permission issues$NC"
    Write-Host "$BLUE  4️⃣  Restart Cursor to generate a new configuration file$NC"
    Write-Host "$BLUE  5️⃣  Wait for the configuration file to be generated (up to 45 seconds)$NC"
    Write-Host "$BLUE  6️⃣  Close Cursor processes$NC"
    Write-Host "$BLUE  7️⃣  Modify the newly generated machine code configuration file$NC"
    Write-Host "$BLUE  8️⃣  Display operation completion statistics$NC"
    Write-Host ""
    Write-Host "$YELLOW⚠️  [Notes]$NC"
    Write-Host "$YELLOW  • Do not manually operate Cursor during script execution$NC"
    Write-Host "$YELLOW  • It is recommended to close all Cursor windows before execution$NC"
    Write-Host "$YELLOW  • You need to restart Cursor after execution is complete$NC"
    Write-Host "$YELLOW  • The original configuration file will be automatically backed up to the backups folder$NC"
}
Write-Host ""

# 🤔 User confirmation
Write-Host "$GREEN🤔 [Confirmation]$NC Please confirm you understand the execution flow above"
$confirmation = Read-Host "Continue execution? (enter y or yes to continue, any other key to exit)"
if ($confirmation -notmatch "^(y|yes)$") {
    Write-Host "$YELLOW👋 [Exiting]$NC User canceled execution, script exiting"
    Read-Host "Press Enter to exit"
    exit 0
}
Write-Host "$GREEN✅ [Confirmed]$NC User confirmed to continue execution"
Write-Host ""

# Get and display Cursor version
function Get-CursorVersion {
    try {
        # Main detection path
        $packagePath = "$env:LOCALAPPDATA\\Programs\\cursor\\resources\\app\\package.json"
        
        if (Test-Path $packagePath) {
            $packageJson = Get-Content $packagePath -Raw | ConvertFrom-Json
            if ($packageJson.version) {
                Write-Host "$GREEN[Info]$NC Currently installed Cursor version: v$($packageJson.version)"
                return $packageJson.version
            }
        }

        # Alternative path detection
        $altPath = "$env:LOCALAPPDATA\\cursor\\resources\\app\\package.json"
        if (Test-Path $altPath) {
            $packageJson = Get-Content $altPath -Raw | ConvertFrom-Json
            if ($packageJson.version) {
                Write-Host "$GREEN[Info]$NC Currently installed Cursor version: v$($packageJson.version)"
                return $packageJson.version
            }
        }

        Write-Host "$YELLOW[Warning]$NC Could not detect Cursor version"
        Write-Host "$YELLOW[Hint]$NC Please ensure Cursor is installed correctly"
        return $null
    }
    catch {
        Write-Host "$RED[Error]$NC Failed to get Cursor version: $_"
        return $null
    }
}

# Get and display version information
$cursorVersion = Get-CursorVersion
Write-Host ""

Write-Host "$YELLOW💡 [Important Note]$NC The latest 1.0.x version is supported"

Write-Host ""

# 🔍 Check and close Cursor processes
Write-Host "$GREEN🔍 [Checking]$NC Checking Cursor processes..."

function Get-ProcessDetails {
    param($processName)
    Write-Host "$BLUE🔍 [Debug]$NC Getting details for $processName process:"
    Get-WmiObject Win32_Process -Filter "name='$processName'" |
        Select-Object ProcessId, ExecutablePath, CommandLine |
        Format-List
}

# Define max retries and wait time
$MAX_RETRIES = 5
$WAIT_TIME = 1

# 🔄 Handle process closing and save process information
function Close-CursorProcessAndSaveInfo {
    param($processName)

    $global:CursorProcessInfo = $null

    $processes = Get-Process -Name $processName -ErrorAction SilentlyContinue
    if ($processes) {
        Write-Host "$YELLOW⚠️  [Warning]$NC Found $processName running"

        # 💾 Save process information for later restart - Fix: ensure getting single process path
        $firstProcess = if ($processes -is [array]) { $processes[0] } else { $processes }
        $processPath = $firstProcess.Path

        # Ensure path is a string and not an array
        if ($processPath -is [array]) {
            $processPath = $processPath[0]
        }

        $global:CursorProcessInfo = @{
            ProcessName = $firstProcess.ProcessName
            Path = $processPath
            StartTime = $firstProcess.StartTime
        }
        Write-Host "$GREEN💾 [Saved]$NC Saved process information: $($global:CursorProcessInfo.Path)"

        Get-ProcessDetails $processName

        Write-Host "$YELLOW🔄 [Action]$NC Attempting to close $processName..."
        Stop-Process -Name $processName -Force

        $retryCount = 0
        while ($retryCount -lt $MAX_RETRIES) {
            $process = Get-Process -Name $processName -ErrorAction SilentlyContinue
            if (-not $process) { break }

            $retryCount++
            if ($retryCount -ge $MAX_RETRIES) {
                Write-Host "$RED❌ [Error]$NC Failed to close $processName after $MAX_RETRIES attempts"
                Get-ProcessDetails $processName
                Write-Host "$RED💥 [Error]$NC Please close the process manually and retry"
                Read-Host "Press Enter to exit"
                exit 1
            }
            Write-Host "$YELLOW⏳ [Waiting]$NC Waiting for process to close, attempt $retryCount/$MAX_RETRIES..."
            Start-Sleep -Seconds $WAIT_TIME
        }
        Write-Host "$GREEN✅ [Success]$NC $processName closed successfully"
    } else {
        Write-Host "$BLUE💡 [Hint]$NC No $processName process found running"
        # Try to find Cursor's installation path
        $cursorPaths = @(
            "$env:LOCALAPPDATA\Programs\cursor\Cursor.exe",
            "$env:PROGRAMFILES\Cursor\Cursor.exe",
            "$env:PROGRAMFILES(X86)\Cursor\Cursor.exe"
        )

        foreach ($path in $cursorPaths) {
            if (Test-Path $path) {
                $global:CursorProcessInfo = @{
                    ProcessName = "Cursor"
                    Path = $path
                    StartTime = $null
                }
                Write-Host "$GREEN💾 [Found]$NC Found Cursor installation path: $path"
                break
            }
        }

        if (-not $global:CursorProcessInfo) {
            Write-Host "$YELLOW⚠️  [Warning]$NC Cursor installation path not found, will use default path"
            $global:CursorProcessInfo = @{
                ProcessName = "Cursor"
                Path = "$env:LOCALAPPDATA\Programs\cursor\Cursor.exe"
                StartTime = $null
            }
        }
    }
}

# 💾 Ensure backup directory exists
if (-not (Test-Path $BACKUP_DIR)) {
    try {
        New-Item -ItemType Directory -Path $BACKUP_DIR -Force | Out-Null
        Write-Host "$GREEN✅ [Backup Directory]$NC Backup directory created successfully: $BACKUP_DIR"
    } catch {
        Write-Host "$YELLOW⚠️  [Warning]$NC Failed to create backup directory: $($_.Exception.Message)"
    }
}

# 🚀 Execute corresponding function based on user choice
if ($executeMode -eq "MODIFY_ONLY") {
    Write-Host "$GREEN🚀 [Starting]$NC Starting Modify Machine Code Only function..."

    # First, perform an environment check
    $envCheck = Test-CursorEnvironment -Mode "MODIFY_ONLY"
    if (-not $envCheck.Success) {
        Write-Host ""
        Write-Host "$RED❌ [Environment Check Failed]$NC Cannot continue, found the following issues:"
        foreach ($issue in $envCheck.Issues) {
            Write-Host "$RED  • ${issue}$NC"
        }
        Write-Host ""
        Write-Host "$YELLOW💡 [Suggestions]$NC Please choose one of the following actions:"
        Write-Host "$BLUE  1️⃣  Choose the 'Reset Environment + Modify Machine Code' option (recommended)$NC"
        Write-Host "$BLUE  2️⃣  Manually start Cursor once, then rerun the script$NC"
        Write-Host "$BLUE  3️⃣  Check if Cursor is installed correctly$NC"
        Write-Host ""
        Read-Host "Press Enter to exit"
        exit 1
    }

    # Execute machine code modification
    $configSuccess = Modify-MachineCodeConfig -Mode "MODIFY_ONLY"

    if ($configSuccess) {
        Write-Host ""
        Write-Host "$GREEN🎉 [Configuration File]$NC Machine code configuration file modification complete!"

        # Add registry modification
        Write-Host "$BLUE🔧 [Registry]$NC Modifying system registry..."
        $registrySuccess = Update-MachineGuid

        # 🔧 New: JavaScript injection function (enhanced device identification bypass)
        Write-Host ""
        Write-Host "$BLUE🔧 [Device ID Bypass]$NC Executing JavaScript injection function..."
        Write-Host "$BLUE💡 [Note]$NC This feature will directly modify Cursor core JS files for a deeper level of device identification bypass"
        $jsSuccess = Modify-CursorJSFiles

        if ($registrySuccess) {
            Write-Host "$GREEN✅ [Registry]$NC System registry modification successful"

            if ($jsSuccess) {
                Write-Host "$GREEN✅ [JavaScript Injection]$NC JavaScript injection function executed successfully"
                Write-Host ""
                Write-Host "$GREEN🎉 [Complete]$NC All machine code modifications complete (enhanced version)!"
                Write-Host "$BLUE📋 [Details]$NC The following modifications have been completed:"
                Write-Host "$GREEN  ✓ Cursor configuration file (storage.json)$NC"
                Write-Host "$GREEN  ✓ System registry (MachineGuid)$NC"
                Write-Host "$GREEN  ✓ JavaScript core injection (device identification bypass)$NC"
            } else {
                Write-Host "$YELLOW⚠️  [JavaScript Injection]$NC JavaScript injection function failed, but other functions succeeded"
                Write-Host ""
                Write-Host "$GREEN🎉 [Complete]$NC All machine code modifications complete!"
                Write-Host "$BLUE📋 [Details]$NC The following modifications have been completed:"
                Write-Host "$GREEN  ✓ Cursor configuration file (storage.json)$NC"
                Write-Host "$GREEN  ✓ System registry (MachineGuid)$NC"
                Write-Host "$YELLOW  ⚠ JavaScript core injection (partially failed)$NC"
            }

            # 🔒 Add configuration file protection mechanism
            Write-Host "$BLUE🔒 [Protection]$NC Setting configuration file protection..."
            try {
                $configPath = "$env:APPDATA\Cursor\User\globalStorage\storage.json"
                $configFile = Get-Item $configPath
                $configFile.IsReadOnly = $true
                Write-Host "$GREEN✅ [Protection]$NC Configuration file set to read-only to prevent Cursor from overwriting modifications"
                Write-Host "$BLUE💡 [Hint]$NC File path: $configPath"
            } catch {
                Write-Host "$YELLOW⚠️  [Protection]$NC Failed to set read-only attribute: $($_.Exception.Message)"
                Write-Host "$BLUE💡 [Suggestion]$NC You can manually right-click the file → Properties → check 'Read-only'"
            }
        } else {
            Write-Host "$YELLOW⚠️  [Registry]$NC Registry modification failed, but configuration file modification succeeded"

            if ($jsSuccess) {
                Write-Host "$GREEN✅ [JavaScript Injection]$NC JavaScript injection function executed successfully"
                Write-Host ""
                Write-Host "$YELLOW🎉 [Partially Complete]$NC Configuration file and JavaScript injection complete, registry modification failed"
                Write-Host "$BLUE💡 [Suggestion]$NC Administrator privileges may be required to modify the registry"
                Write-Host "$BLUE📋 [Details]$NC The following modifications have been completed:"
                Write-Host "$GREEN  ✓ Cursor configuration file (storage.json)$NC"
                Write-Host "$YELLOW  ⚠ System registry (MachineGuid) - Failed$NC"
                Write-Host "$GREEN  ✓ JavaScript core injection (device identification bypass)$NC"
            } else {
                Write-Host "$YELLOW⚠️  [JavaScript Injection]$NC JavaScript injection function failed"
                Write-Host ""
                Write-Host "$YELLOW🎉 [Partially Complete]$NC Configuration file modification complete, registry and JavaScript injection failed"
                Write-Host "$BLUE💡 [Suggestion]$NC Administrator privileges may be required to modify the registry"
            }

            # 🔒 Protect the configuration file even if registry modification fails
            Write-Host "$BLUE🔒 [Protection]$NC Setting configuration file protection..."
            try {
                $configPath = "$env:APPDATA\Cursor\User\globalStorage\storage.json"
                $configFile = Get-Item $configPath
                $configFile.IsReadOnly = $true
                Write-Host "$GREEN✅ [Protection]$NC Configuration file set to read-only to prevent Cursor from overwriting modifications"
                Write-Host "$BLUE💡 [Hint]$NC File path: $configPath"
            } catch {
                Write-Host "$YELLOW⚠️  [Protection]$NC Failed to set read-only attribute: $($_.Exception.Message)"
                Write-Host "$BLUE💡 [Suggestion]$NC You can manually right-click the file → Properties → check 'Read-only'"
            }
        }

        Write-Host "$BLUE💡 [Hint]$NC You can now start Cursor to use the new machine code configuration"
    } else {
        Write-Host ""
        Write-Host "$RED❌ [Failed]$NC Machine code modification failed!"
        Write-Host "$YELLOW💡 [Suggestion]$NC Please try the 'Reset Environment + Modify Machine Code' option"
    }
} else {
    # Full reset environment + modify machine code process
    Write-Host "$GREEN🚀 [Starting]$NC Starting Reset Environment + Modify Machine Code function..."

    # 🚀 Close all Cursor processes and save information
    Close-CursorProcessAndSaveInfo "Cursor"
    if (-not $global:CursorProcessInfo) {
        Close-CursorProcessAndSaveInfo "cursor"
    }

    # 🚨 Important warning message
    Write-Host ""
    Write-Host "$RED🚨 [Important Warning]$NC ============================================"
    Write-Host "$YELLOW⚠️  [Risk Control Reminder]$NC Cursor's risk control mechanism is very strict!"
    Write-Host "$YELLOW⚠️  [Must Delete]$NC You must completely delete the specified folders, there can be no residual settings"
    Write-Host "$YELLOW⚠️  [Anti-Trial Expiration]$NC Only a thorough cleanup can effectively prevent the Pro trial status from expiring"
    Write-Host "$RED🚨 [Important Warning]$NC ============================================"
    Write-Host ""

    # 🎯 Execute Cursor Pro trial anti-expiration folder deletion function
    Write-Host "$GREEN🚀 [Starting]$NC Starting core function..."
    Remove-CursorTrialFolders



    # 🔄 Restart Cursor to let it regenerate the configuration file
    Restart-CursorAndWait

    # 🛠️ Modify machine code configuration
    $configSuccess = Modify-MachineCodeConfig
    
    # 🧹 Perform Cursor initialization cleanup
    Invoke-CursorInitialization

    if ($configSuccess) {
        Write-Host ""
        Write-Host "$GREEN🎉 [Configuration File]$NC Machine code configuration file modification complete!"

        # Add registry modification
        Write-Host "$BLUE🔧 [Registry]$NC Modifying system registry..."
        $registrySuccess = Update-MachineGuid

        # 🔧 New: JavaScript injection function (enhanced device identification bypass)
        Write-Host ""
        Write-Host "$BLUE🔧 [Device ID Bypass]$NC Executing JavaScript injection function..."
        Write-Host "$BLUE💡 [Note]$NC This feature will directly modify Cursor core JS files for a deeper level of device identification bypass"
        $jsSuccess = Modify-CursorJSFiles

        if ($registrySuccess) {
            Write-Host "$GREEN✅ [Registry]$NC System registry modification successful"

            if ($jsSuccess) {
                Write-Host "$GREEN✅ [JavaScript Injection]$NC JavaScript injection function executed successfully"
                Write-Host ""
                Write-Host "$GREEN🎉 [Complete]$NC All operations complete (enhanced version)!"
                Write-Host "$BLUE📋 [Details]$NC The following operations have been completed:"
                Write-Host "$GREEN  ✓ Deleted Cursor trial-related folders$NC"
                Write-Host "$GREEN  ✓ Cursor initialization cleanup$NC"
                Write-Host "$GREEN  ✓ Regenerated configuration file$NC"
                Write-Host "$GREEN  ✓ Modified machine code configuration$NC"
                Write-Host "$GREEN  ✓ Modified system registry$NC"
                Write-Host "$GREEN  ✓ JavaScript core injection (device identification bypass)$NC"
            } else {
                Write-Host "$YELLOW⚠️  [JavaScript Injection]$NC JavaScript injection function failed, but other functions succeeded"
                Write-Host ""
                Write-Host "$GREEN🎉 [Complete]$NC All operations complete!"
                Write-Host "$BLUE📋 [Details]$NC The following operations have been completed:"
                Write-Host "$GREEN  ✓ Deleted Cursor trial-related folders$NC"
                Write-Host "$GREEN  ✓ Cursor initialization cleanup$NC"
                Write-Host "$GREEN  ✓ Regenerated configuration file$NC"
                Write-Host "$GREEN  ✓ Modified machine code configuration$NC"
                Write-Host "$GREEN  ✓ Modified system registry$NC"
                Write-Host "$YELLOW  ⚠ JavaScript core injection (partially failed)$NC"
            }

            # 🔒 Add configuration file protection mechanism
            Write-Host "$BLUE🔒 [Protection]$NC Setting configuration file protection..."
            try {
                $configPath = "$env:APPDATA\Cursor\User\globalStorage\storage.json"
                $configFile = Get-Item $configPath
                $configFile.IsReadOnly = $true
                Write-Host "$GREEN✅ [Protection]$NC Configuration file set to read-only to prevent Cursor from overwriting modifications"
                Write-Host "$BLUE💡 [Hint]$NC File path: $configPath"
            } catch {
                Write-Host "$YELLOW⚠️  [Protection]$NC Failed to set read-only attribute: $($_.Exception.Message)"
                Write-Host "$BLUE💡 [Suggestion]$NC You can manually right-click the file → Properties → check 'Read-only'"
            }
        } else {
            Write-Host "$YELLOW⚠️  [Registry]$NC Registry modification failed, but other operations succeeded"

            if ($jsSuccess) {
                Write-Host "$GREEN✅ [JavaScript Injection]$NC JavaScript injection function executed successfully"
                Write-Host ""
                Write-Host "$YELLOW🎉 [Partially Complete]$NC Most operations complete, registry modification failed"
                Write-Host "$BLUE💡 [Suggestion]$NC Administrator privileges may be required to modify the registry"
                Write-Host "$BLUE📋 [Details]$NC The following operations have been completed:"
                Write-Host "$GREEN  ✓ Deleted Cursor trial-related folders$NC"
                Write-Host "$GREEN  ✓ Cursor initialization cleanup$NC"
                Write-Host "$GREEN  ✓ Regenerated configuration file$NC"
                Write-Host "$GREEN  ✓ Modified machine code configuration$NC"
                Write-Host "$YELLOW  ⚠ Modified system registry - Failed$NC"
                Write-Host "$GREEN  ✓ JavaScript core injection (device identification bypass)$NC"
            } else {
                Write-Host "$YELLOW⚠️  [JavaScript Injection]$NC JavaScript injection function failed"
                Write-Host ""
                Write-Host "$YELLOW🎉 [Partially Complete]$NC Most operations complete, registry and JavaScript injection failed"
                Write-Host "$BLUE💡 [Suggestion]$NC Administrator privileges may be required to modify the registry"
            }

            # 🔒 Protect the configuration file even if registry modification fails
            Write-Host "$BLUE🔒 [Protection]$NC Setting configuration file protection..."
            try {
                $configPath = "$env:APPDATA\Cursor\User\globalStorage\storage.json"
                $configFile = Get-Item $configPath
                $configFile.IsReadOnly = $true
                Write-Host "$GREEN✅ [Protection]$NC Configuration file set to read-only to prevent Cursor from overwriting modifications"
                Write-Host "$BLUE💡 [Hint]$NC File path: $configPath"
            } catch {
                Write-Host "$YELLOW⚠️  [Protection]$NC Failed to set read-only attribute: $($_.Exception.Message)"
                Write-Host "$BLUE💡 [Suggestion]$NC You can manually right-click the file → Properties → check 'Read-only'"
            }
        }
    } else {
        Write-Host ""
        Write-Host "$RED❌ [Failed]$NC Machine code configuration modification failed!"
        Write-Host "$YELLOW💡 [Suggestion]$NC Please check the error messages and retry"
    }
}


# 📱 Display public account information
Write-Host ""
Write-Host "$GREEN================================$NC"
Write-Host "$YELLOW📱  Follow the public account [JianbingGuoziJuanAI] to discuss more Cursor tips and AI knowledge (script is free, follow the public account to join the group for more tips and experts)  $NC"
Write-Host "$GREEN================================$NC"
Write-Host ""

# 🎉 Script execution complete
Write-Host "$GREEN🎉 [Script Complete]$NC Thank you for using the Cursor Machine Code Modifier Tool!"
Write-Host "$BLUE💡 [Hint]$NC If you have any problems, please refer to the public account or rerun the script"
Write-Host ""
Read-Host "Press Enter to exit"
exit 0
