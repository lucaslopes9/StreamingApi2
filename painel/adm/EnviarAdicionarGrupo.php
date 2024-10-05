<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('OpcoesGrupoAcesso');
$VerificarAcesso = VerificarAcesso('opcoes', $ColunaAcesso);
$OpcoesGrupoAcesso = $VerificarAcesso[0];
 
if($OpcoesGrupoAcesso == 'S'){

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
	
	$EditarNome = (isset($_POST['EditarNome'])) ? trim($_POST['EditarNome']) : "";
	$CadUser = InfoUser(2);
	
	$SQL = "SELECT nome FROM grupodeacesso WHERE nome = :nome AND CadUser = :CadUser";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':nome', $EditarNome, PDO::PARAM_STR); 
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR); 
	$SQL->execute();
	$TotalNome = count($SQL->fetchAll());
	
	if(empty($EditarNome)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['nuco'], "danger");
	}
	elseif($TotalNome > 0){
		echo MensagemAlerta($_TRA['erro'], $_TRA['egdaje'], "danger");
	}
	else{
		
	$SQL = "INSERT INTO grupodeacesso (
			CadUser,
			nome
            ) VALUES (
			:CadUser,
			:nome
			)";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
	$SQL->bindParam(':nome', $EditarNome, PDO::PARAM_STR);
	$SQL->execute(); 
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['adcs'], "success", "index.php?p=grupo-de-acesso");
	}
		
		
	}
}

}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}

?>