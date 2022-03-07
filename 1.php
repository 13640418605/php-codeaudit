<script>
	first_node = undefined;
	function fuckopen(fuck,url)
	{
		window.open(url);
		fuck.style="color:#00F"
		if(first_node != undefined)
		{
			document.getElementById(first_node).style = "";
		}
		first_node = fuck.id;
	}
</script>
<form method="post" action="#" id="req_form">
	路径:<input type="text" name="dir_path" id="dir_path" value="<?=$_POST["dir_path"]?>"/>
	漏洞:<select name="loudong_type" selected="selected">
	  <option value ="sqli">sql注入</option>
	  <option value ="include">文件包含</option>
	  <option value ="read">文件读取</option>
	  <option value ="write">文件写入</option>
	  <option value ="del">文件删除</option>
	  <option value ="do_dir">目录操作</option>
	  <option value="command">命令执行</option>
	  <option value="fugai">变量覆盖</option>
	  <option value="unserialize">反序列化</option>
	  <option value="ssrf">ssrf</option>
	  <option value="xxe">xxe</option>
	</select>
	<input type="submit" name="submit" value="提交"/>
</form>
<table border="8">
	<th>序号</th>
	<th>漏洞</th>
	<th>行号</th>
	<th>代码</th>
	<th>路径</th>
<?php
require 'vendor/autoload.php';
use PhpParser\ParserFactory;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;
use PhpParser\Node;
use PhpParser\PrettyPrinter;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Name;
use PhpParser\Node\Expr\Include_;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Expr\Eval_;
function check()
{
	global $filename;
	$code = file_get_contents($filename);
	$phpFactory = new ParserFactory();
	$parser = $phpFactory->create(ParserFactory::PREFER_PHP7);
	try{
		$ast = $parser->parse($code);	
	}catch(Exception $e){
		//echo "发生错误$filename<br>";
		return;
	}
	$traverser = new NodeTraverser;
	//$filename = $filename;
	//echo $filename;
	$traverser->addVisitor(new class extends NodeVisitorAbstract {
		public function leaveNode(Node $node) {
			global $target_arr;
			global $filename;
			global $count;
			//var_dump($node);
			if ($node instanceof FuncCall && $node->name instanceof Name && is_array($node->name->parts)) {
				//   
				$func_name = $node->name->parts[0];
				//var_dump($target_arr);
				if(in_array($func_name,$target_arr)){
					//var_dump($node);
					$start_line = $node->attributes["startLine"];
					$end_line = $node->attributes["endLine"];
					array_push($_SESSION["result"],$filename);
					$prettyPrinter = new PrettyPrinter\Standard;
					$code = $prettyPrinter->prettyPrintExpr($node);
					echo '<tr>';
					echo "<td>$count</td><td>".$func_name."函数</td> <td>$start_line</td><td>$code</td><td><a id=\"$count\" onclick=\"javascript:fuckopen(this,'3.php?id=$count')\">$filename</a></td>";//<br>
					echo '</tr>';
					$count += 1;
				}
			}
			else if($node instanceof Eval_ && in_array("system",$target_arr))
			{
				$start_line = $node->attributes["startLine"];
				$end_line = $node->attributes["endLine"];
				array_push($_SESSION["result"],$filename);
				$prettyPrinter = new PrettyPrinter\Standard;
				$code = $prettyPrinter->prettyPrintExpr($node);
				echo '<tr>';
				echo "<td>$count</td><td>".$func_name."函数</td> <td>$start_line</td><td>$code</td><td><a id=\"$count\" onclick=\"javascript:fuckopen(this,'3.php?id=$count')\">$filename</a></td>";//<br>
				echo '</tr>';
				$count += 1;
			}
		}
	});
	$traverser->traverse($ast);
}
function var_check()
{
	global $filename;
	$code = file_get_contents($filename);
	$phpFactory = new ParserFactory();
	$parser = $phpFactory->create(ParserFactory::PREFER_PHP7);
	try{
		$ast = $parser->parse($code);	
	}catch(Exception $e){
		return;
	}
	$traverser = new NodeTraverser;
	$traverser->addVisitor(new class extends NodeVisitorAbstract {
		public function leaveNode(Node $node) {
			global $filename;
			global $count;
			if ($node instanceof Variable && $node->name instanceof Variable) {
				$func_name = "$$";
				$start_line = $node->attributes["startLine"];
				$end_line = $node->attributes["endLine"];
				array_push($_SESSION["result"],$filename);
				$prettyPrinter = new PrettyPrinter\Standard;
				$code = $prettyPrinter->prettyPrintExpr($node);
				echo '<tr>';
				echo "<td>$count</td><td>".$func_name."函数</td> <td>$start_line</td><td>$code</td><td><a id=\"$count\" onclick=\"javascript:fuckopen(this,'3.php?id=$count')\">$filename</a></td>";//<br>
				echo '</tr>';
				$count += 1;
			}
		}
	});
	$traverser->traverse($ast);
}
function include_check()
{
	global $filename;
	$code = file_get_contents($filename);
	$phpFactory = new ParserFactory();
	$parser = $phpFactory->create(ParserFactory::PREFER_PHP7);
	try{
		$ast = $parser->parse($code);	
	}catch(Exception $e){
		return;
	}
	$traverser = new NodeTraverser;
	$traverser->addVisitor(new class extends NodeVisitorAbstract {
		public function leaveNode(Node $node) {
			global $filename;
			global $count;
			if ($node instanceof Include_) {
				$func_name = "include";
				$start_line = $node->attributes["startLine"];
				$end_line = $node->attributes["endLine"];
				array_push($_SESSION["result"],$filename);
				$prettyPrinter = new PrettyPrinter\Standard;
				$code = $prettyPrinter->prettyPrintExpr($node);
				echo '<tr>';
				echo "<td>$count</td><td>".$func_name."函数</td> <td>$start_line</td><td>$code</td><td><a id=\"$count\" onclick=\"javascript:fuckopen(this,'3.php?id=$count')\">$filename</a></td>";
				echo '</tr>';
				$count += 1;
			}
		}
	});
	$traverser->traverse($ast);
}
function dirList($dir_path = '') {
	global $all_path;
    if(is_dir($dir_path)) {
        $dirs = opendir($dir_path);
        if($dirs) {
            while(($file = readdir($dirs)) !== false) {
                if($file !== '.' && $file !== '..') {
                    if(is_dir($dir_path . '/' . $file)) {
                        dirList($dir_path . '/' . $file);
                    } else {
                    	$kk_name = $dir_path . '/' . $file;
                    	array_push($all_path,$kk_name);
                    }
                }
            }
            closedir($dirs);
        }
    } else {
        echo '目录不存在！';
        exit(1);
    }

}

if(isset($_POST["submit"]))
{
	session_start();
	$_SESSION["result"] = [];
	$dir_path = $_POST["dir_path"];
	$count = 0;
	$all_path = [];
	$loudong_type = $_POST["loudong_type"];
	switch($loudong_type)
	{
		case "sqli":
			$target_arr = ["mysqli_query","mysql_query"];
			break;
		case "include":
			//$target_arr = ["include","require","include_once","require_once"];
			break;
		case "read":
			$target_arr = ["file_get_contents","file","fgets","fread","readfile","fpassthru","parse_ini_file","highlight_file","fgetss","show_source","bzopen","fgetc","fgetcsv","fscanf"]; //"fopen",
			break;
		case "write":
			$target_arr = ["move_uploaded_file","file_put_contents","fwrite","fputs","fprintf","fputcsv","copy","rename"];
			break;
		case "command":
			$target_arr = ["assert","create_function","array_map","call_user_func","call_user_func_array","array_filter","usort","uasort","ob_start","dl","putenv","system","exec","shell_exec","passthru","popen","proc_open","pcntl_exec"];
			//preg_replace /e new COM('WScript.shell') `` ${phpinfo()}
			break;
		case "fugai":
			$target_arr = ["extract","parse_str","import_request_variables"];
			break;
		case "unserialize":
			$target_arr = ["unserialize"];
			break;
		case "del":
			$target_arr = ["unlink","unset"];
			break;
		case "do_dir":
			$target_arr = ["mkdir","rmdir","scandir","readdir","dir","glob"];
			break;
		case "ssrf":
			$target_arr = ["curl_exec","fsockopen"];
			break;
		case "xxe":
			$target_arr = ["simplexml_import_dom","simplexml_load_string","simplexml_load_file"];
			break;
		default:
			echo "没有这个漏洞类型!!!";
			exit(1);
	}
	dirList($dir_path);
	foreach($all_path as $k=>$v)
	{
		$filename = $v;
		if($loudong_type == "include")
		{
			include_check();
		}
		else if($loudong_type == "fugai")
		{
			var_check();
			check();
		}
		else
		{
			check();
		}
	}
}
?>
</table>