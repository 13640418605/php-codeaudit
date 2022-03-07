<?php
	session_start();
	if(isset($_GET["id"]) && !empty($_SESSION["result"]) && array_key_exists($_GET["id"],$_SESSION["result"]))
	{
		$file = $_SESSION["result"][$_GET["id"]];
		popen('"D:\Sublime Text 3.3126x64\sublime_text.exe" "'.$file.'"',"r");
	}
	else
	{
		echo "找不到该id";
	}
	echo '<script>window.close();</script>';
?>