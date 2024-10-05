<?php
header("Content-type: text/xml; charset=UTF-8");

include_once("functions.php");
include("conexao.php");

	$key = empty($_GET['key']) ? "" : $_GET['key'];
	$IPOnline = $_SERVER['REMOTE_ADDR'];

	//Selecionar dados do servidor
	$SQL = "SELECT senha, ip, iplock FROM painel_config";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->execute();
	$Ln = $SQL->fetch();
	$senha = empty($Ln['senha']) ? "" : $Ln['senha'];
	$ip = empty($Ln['ip']) ? "" : $Ln['ip'];
	$iplock = empty($Ln['iplock']) ? "S" : $Ln['iplock'];
	
	$ArrayIP = array();
	$ips = explode(";", $ip);
	for($i = 0; $i < count($ips); $i++){
		$ArrayIP[] = trim($ips[$i]);
	}
		
	if( !empty($key) && !empty($senha) && ($key == md5($senha)) && in_array($IPOnline, $ArrayIP) && ($iplock == "S") || !empty($key) && !empty($senha) && ($key == md5($senha)) && ($iplock == "N") ){
	
	$DataAtual = strtotime(date('Y-m-d'));
	$xml = "S";
	$SQL = "(SELECT usuario, senha, perfil, conexao, data_premio, bloqueado FROM usuario WHERE xml = :xml) UNION ALL (SELECT usuario, senha, perfil, conexao, data_premio, bloqueado FROM teste WHERE xml = :xml) ORDER by usuario ASC";
	$SQL = $painel_user->prepare($SQL);
	$SQL->bindParam(':xml', $xml, PDO::PARAM_STR);
	$SQL->execute();
	
	$ExibirXML = "<xml-user-manager ver=\"1.0\">\n";
	while($Ln = $SQL->fetch()){
		
		$perfil = str_replace("]["," ",$Ln['perfil']);
		$perfil = str_replace("["," ",$perfil);
		$perfil = str_replace("]"," ",$perfil);
		$perfil = trim($perfil);
		
		$usuario = trim($Ln['usuario']);
		$senha = trim($Ln['senha']);
		$conexao = trim($Ln['conexao']);
		$data_premio = trim($Ln['data_premio']);
		$bloqueado = trim($Ln['bloqueado']);
		$DataAtual = strtotime(date('Y-m-d'));
		
		if( ($data_premio >= $DataAtual) && ($bloqueado == "N") ){
		$ExibirXML .= "<user name=\"".$usuario."\" password=\"".$senha."\" display-name=\"".$usuario."\" profiles=\"".$perfil."\" max-connections=\"".$conexao."\" />\n";
		}

	}
	$ExibirXML .= "</xml-user-manager>";
	
	echo $ExibirXML;
}
?>