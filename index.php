<?php

//正規リクエストを判定するための文字列
define('VERIFY_TOKEN', 'weather');
define('ATOM_SAVE_PATH', './atom/');

//タイムゾーンの指定
date_default_timezone_set('Asia/Tokyo');

$method = $_SERVER['REQUEST_METHOD'];

if ( $method === 'GET' ) {
	$hubMode      = $_REQUEST['hub_mode'];
	$hubChallenge = $_REQUEST['hub_challenge'];

	if ( $_REQUEST['hub_verify_token'] !== VERIFY_TOKEN ) {
		header('HTTP/1.1 404 "Unknown Request"', null, 404);
		exit("Unknown Request");
	}

	if ( ($hubMode === 'subscribe') || ($hubMode === 'unsubscribe') ) {
		header('HTTP/1.1 200 "OK"', null, 200);
		header('Content-Type:text/plain');
		echo $hubChallenge;
	} else {
		header('HTTP/1.1 404 "Not Found"', null, 404);
	}
}

if ( $method === 'POST' ) {
	$string = file_get_contents("php://input");

	//verify_tokenを確認
	if ( isset($_SERVER['HTTP_X_HUB_SIGNATURE']) ) {
		$sign = explode('=', $_SERVER['HTTP_X_HUB_SIGNATURE']);
		$sha1  = hash_hmac("sha1", $string, VERIFY_TOKEN);
		if ( $sign[1] != $sha1 ) {
            $log = fopen('./log/error.log', 'w');
            fwrite($log, $sha1);
            fclose($log);

            header('HTTP/1.1 404 "Invalid X-Hub-Signature"', null, 404);
            exit("Invalid X-Hub-Signature");
		}
	}

	$fp     = fopen(ATOM_SAVE_PATH . date('YmdHis')."_atom.xml", "w");
	fwrite($fp, $string);
	fclose($fp);
}
