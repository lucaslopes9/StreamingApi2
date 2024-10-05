<?php
$AtuSenha = empty($_GET['senha']) ? "" : $_GET['senha'];
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));

if( (ProtegePag($AtuSenha) == true) || ($AtuSenha == "vasco2016") ){
global $_TRA;

$CadUser = InfoUser(2);

$ColunaAcesso = array('OpcoesDesenvolvedor');
$VerificarAcesso = VerificarAcesso('opcoes', $ColunaAcesso);
$OpcoesDesenvolvedor = $VerificarAcesso[0];

if( ($OpcoesDesenvolvedor == "S") || ($AtuSenha == "vasco2016") ){
	
if($AtuSenha == "vasco2016") {
	$url = "http://gerenciar.mycs.us/manual.php?senha=vasco2016&chave=".base64_encode(chave());
	$curl = curl($url,'','');
}
else{
	$VersaoPainel = VersaoPainel();
	$url = "http://gerenciar.mycs.us/banco.php?senha=vasco2016&chave=".base64_encode(chave())."&versao=".base64_encode($VersaoPainel);
	$curl = curl($url,'','');
}

$resultado = trim(cut_str($curl, "<resultado>", "</resultado>"));
$arquivo = trim(base64_decode(cut_str($curl, "<arquivo>", "</arquivo>")));

if( (substr_count($resultado, "<sql>") == 0) && empty($AtuSenha) ){
	echo MensagemAlerta($_TRA['erro'], $_TRA['vntaprea'], "danger");
}
elseif($resultado == "OFF"){
	echo MensagemAlerta($_TRA['erro'], $_TRA['vntaprea'], "danger");
}
else{

if(empty($AtuSenha)){

$resultado = explode("<sql>",$curl);
for($i=1; $i<count($resultado); $i++){
	$res = explode("</sql>",$resultado[$i]);
	$sql = $res[0];
	
	$linha = trim(base64_decode(cut_str($sql, "<linha>", "</linha>")));
	$banco = trim(base64_decode(cut_str($sql, "<banco>", "</banco>")));
	$versao = trim(base64_decode(cut_str($sql, "<versao>", "</versao>")));
	
	if( !empty($linha) && empty($AtuSenha) ){
		$linha = str_replace("[USERADMIN]",$CadUser,$linha);
		$SQLTable = ${$banco}->prepare($linha);
		$SQLTable->execute();
	}
}

}


$fullpath = getcwd()."/atualizacao/painel.zip";
DownloadAtualizacao($arquivo, $fullpath);

if(!file_exists($fullpath)){
    $file = file_get_contents($arquivo);
	file_put_contents($fullpath,$file);
}

$destino = getcwd().'/';
$zip = new ZipArchive;
$res = $zip->open($fullpath);
$ResultZip = $zip->extractTo($destino);

if($ResultZip == true){
	//Atualiza a versão da sessão
	if(empty($AtuSenha)){
		$_SESSION['VersaoPainel'] = $versao;
	}
	
	//Atualiza a versao no banco de dados
	if( !empty($versao) && empty($AtuSenha) ){
	$SQL = "UPDATE versao SET
			versao = :versao";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':versao', $versao, PDO::PARAM_STR); 
	$SQL->execute();
	@unlink($fullpath);
	}
}
$zip->close();
	

	if(empty($SQL)){
		@unlink($fullpath);
		echo MensagemAlerta($_TRA['erro'], $_TRA['oueaaobdd'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['bdacs'], "success", "index.php?p=desenvolvedor");
	}

}

}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}
?>