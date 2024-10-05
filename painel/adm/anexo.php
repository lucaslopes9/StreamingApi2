<?php
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$anexo = empty($_GET['a']) ? "" : base64_decode($_GET['a']);

if(empty($anexo)){
?>
	<script type='text/javascript'> 
	alert('<?php echo $_TRA['eane']; ?>');
	exit;
	</script>
<?php
}else{
$caminho_download = "suporte/".$anexo;
if(!file_exists($caminho_download)){
?>
	<script type='text/javascript'> 
	alert('<?php echo $_TRA['eane']; ?>');
	exit;
	</script>
<?php
}
else{
header('Cache-control: private');
header('Content-Type: application/octet-stream');
header('Content-Length: '.filesize($caminho_download));
header('Content-Disposition: filename='.$anexo);
header("Content-Disposition: attachment; filename=".$anexo);
readfile($caminho_download);
}
}
}else{
	echo Redirecionar('login.php');
}	
?>